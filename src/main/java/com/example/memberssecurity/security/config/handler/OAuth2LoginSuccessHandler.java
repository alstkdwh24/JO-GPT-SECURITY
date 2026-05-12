package com.example.memberssecurity.security.config.handler;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.example.entitycom.entity.member.Members;
import com.example.memberssecurity.member.service.MemberService;
import com.example.memberssecurity.security.config.dto.social.dto.GithubUserInfo;
import com.example.memberssecurity.security.config.dto.social.dto.GoogleUserInfo;
import com.example.memberssecurity.security.config.dto.social.dto.KakaoUserInfo;
import com.example.memberssecurity.security.config.dto.social.dto.NaverUserInfo;
import com.example.memberssecurity.security.config.dto.social.dto.SocialUserInfo;
import com.example.memberssecurity.security.config.jwt.JWTUtils;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JWTUtils jwtUtils;
    private final MemberService memberService;
    // - 서버 템플릿이면 "http://localhost:8086/auth/success" 같은 페이지
    @Value("${spring.frontend.url}")
    private String frontendUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        log.debug("Authentication success: {}", authentication);
        if (!(authentication instanceof OAuth2AuthenticationToken oauthToken)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid authentication type");
            return;
        }

        SocialUserInfo userInfo = getSocialUserInfo(oauthToken);
        MemberService.OAuthResult result = memberService.upsertOAuthUser(userInfo);
        Members member = result.member();
        log.debug("OAuth2 로그인 성공: member={}, isNew={}", member, result.isNew());

        // 1시간 유효 토큰 생성
        String accessToken = jwtUtils.createToken(member.getMemberKey(), member.getRole(), 60 * 60 * 1000L);

        // 쿠키 설정
        Cookie cookie = new Cookie("ACCESS_TOKEN", accessToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(60 * 60);
        response.addCookie(cookie);

        // 닉네임이 임시값(memberId 형식)인 경우 닉네임 설정 화면 표시
        String tempMemberId = userInfo.getProvider() + "_" + userInfo.getProviderId();
        boolean needsNickname = result.isNew() || tempMemberId.equals(result.member().getNickname());

        String redirectUrl = frontendUrl + "?token=" + accessToken;
        if (needsNickname) {
            redirectUrl += "&needsNickname=true";
            // 네이버만 기존 닉네임 사용 여부를 선택할 수 있도록 socialNickname 전달
            if ("naver".equals(userInfo.getProvider())) {
                String suggested = userInfo.getSuggestedNickname();
                if (suggested != null && !suggested.isBlank()) {
                    redirectUrl += "&socialNickname=" + URLEncoder.encode(suggested, StandardCharsets.UTF_8);
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

        SocialUserInfo userInfo = switch (registrationId.toLowerCase()) {
            case "google" -> new GoogleUserInfo(attributes);
            case "kakao" -> new KakaoUserInfo(attributes);
            case "naver" -> new NaverUserInfo(attributes);
            case "github" -> new GithubUserInfo(attributes);
            default -> throw new IllegalArgumentException("Unsupported provider: " + registrationId);
        };
        return userInfo;
    }
}
