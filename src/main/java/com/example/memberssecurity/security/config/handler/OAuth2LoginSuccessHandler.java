package com.example.memberssecurity.security.config.handler;

import com.example.entitycom.entity.member.Members;
import com.example.memberssecurity.member.service.ConnectedAccountsService;
import com.example.memberssecurity.member.service.MemberService;
import com.example.memberssecurity.security.config.dto.social.dto.*;
import com.example.memberssecurity.security.config.jwt.JWTUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JWTUtils jwtUtils;
    private final MemberService memberService;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final ConnectedAccountsService connectedAccountsService;

    @Value("${spring.frontend.url}")
    private String frontendUrl;

    @Value("${expiration_time}")
    private Long expirationTime;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        log.debug("Authentication success: {}", authentication);
        if (!(authentication instanceof OAuth2AuthenticationToken oauthToken)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid authentication type");
            return;
        }

        // google-connect 분기 (Google API 계정 연결)
        if ("google-connect".equals(oauthToken.getAuthorizedClientRegistrationId())) {
            handleGoogleConnect(request, response, oauthToken);
            return;
        }

        SocialUserInfo userInfo = getSocialUserInfo(oauthToken);
        MemberService.OAuthResult result = memberService.upsertOAuthUser(userInfo);
        Members member = result.member();
        log.debug("OAuth2 로그인 성공: member={}, isNew={}", member, result.isNew());

        String accessToken = jwtUtils.createToken(member.getMemberKey(), member.getRole(), expirationTime);
        String refreshToken = jwtUtils.createRefreshToken(member.getMemberKey(), member.getRole());

        Cookie refreshCookie = new Cookie("REFRESH_TOKEN", refreshToken);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setSecure(true);
        refreshCookie.setPath("/");
        refreshCookie.setMaxAge(60 * 60 * 24 * 7);
        response.addCookie(refreshCookie);

        Cookie cookie = new Cookie("ACCESS_TOKEN", accessToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(60 * 60 * 3);
        response.addCookie(cookie);

        String tempMemberId = userInfo.getProvider() + "_" + userInfo.getProviderId();
        boolean needsNickname = result.isNew() || tempMemberId.equals(result.member().getNickname());

        String clientType = (String) request.getSession().getAttribute("client");
        boolean isElectron = "electron".equals(clientType);
        request.getSession().removeAttribute("client");

        String redirectUrl;
        if (isElectron) {
            redirectUrl = "jo-gpt://auth?token=" + accessToken + "&refreshtoken=" + refreshToken;
            if (needsNickname) {
                redirectUrl += "&needsNickname=true";
                if ("naver".equals(userInfo.getProvider())) {
                    String suggested = userInfo.getSuggestedNickname();
                    if (suggested != null && !suggested.isBlank()) {
                        redirectUrl += "&socialNickname=" + URLEncoder.encode(suggested, StandardCharsets.UTF_8);
                    }
                }
            }
        } else {
            redirectUrl = frontendUrl + (needsNickname ? "?needsNickname=true" : "");
            if (needsNickname) {
                redirectUrl += "&needsNickname=true";
                if ("naver".equals(userInfo.getProvider())) {
                    String suggested = userInfo.getSuggestedNickname();
                    if (suggested != null && !suggested.isBlank()) {
                        redirectUrl += "&socialNickname=" + URLEncoder.encode(suggested, StandardCharsets.UTF_8);
                    }
                }
            }
        }
        response.sendRedirect(redirectUrl);
        log.debug("Redirected to bridge page with token: {}", accessToken);
    }

    private static @NonNull SocialUserInfo getSocialUserInfo(OAuth2AuthenticationToken oauthToken) {
        String registrationId = oauthToken.getAuthorizedClientRegistrationId();
        OAuth2User oauth2User = oauthToken.getPrincipal();
        assert oauth2User != null;
        Map<String, Object> attributes = oauth2User.getAttributes();

        return switch (registrationId.toLowerCase()) {
            case "google" -> new GoogleUserInfo(attributes);
            case "kakao" -> new KakaoUserInfo(attributes);
            case "naver" -> new NaverUserInfo(attributes);
            case "github" -> new GithubUserInfo(attributes);
            default -> throw new IllegalArgumentException("Unsupported provider: " + registrationId);
        };
    }

    // ✅ 쿠키에서 memberKey 꺼내도록 수정
    private void handleGoogleConnect(HttpServletRequest request, HttpServletResponse response,
            OAuth2AuthenticationToken oauthToken) throws IOException {

        // 쿠키에서 connectingMemberKey 꺼내기
        String memberKeyStr = null;
        if (request.getCookies() != null) {
            for (Cookie c : request.getCookies()) {
                if ("connectingMemberKey".equals(c.getName())) {
                    memberKeyStr = c.getValue();
                    break;
                }
            }
        }

        // 쿠키 삭제
        Cookie deleteCookie = new Cookie("connectingMemberKey", null);
        deleteCookie.setPath("/");
        deleteCookie.setMaxAge(0);
        response.addCookie(deleteCookie);

        if (memberKeyStr == null) {
            log.error("[handleGoogleConnect] connectingMemberKey 쿠키 없음!");
            response.sendRedirect(frontendUrl + "?error=connect_failed");
            return;
        }

        OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                "google-connect", oauthToken.getName());

        String accessToken = authorizedClient.getAccessToken().getTokenValue();
        String refreshToken = authorizedClient.getRefreshToken() != null
                ? authorizedClient.getRefreshToken().getTokenValue() : null;
        String email = (String) oauthToken.getPrincipal().getAttributes().get("email");

        connectedAccountsService.saveOrUpdate(Long.parseLong(memberKeyStr), "google", email, accessToken, refreshToken);

        response.sendRedirect(frontendUrl + "?connected=google");
    }
}
