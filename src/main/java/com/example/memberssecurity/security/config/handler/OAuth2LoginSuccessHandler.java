package com.example.memberssecurity.security.config.handler;

import com.example.memberssecurity.security.config.dto.social.dto.*;
import com.example.memberssecurity.security.config.jwt.JWTUtils;
import com.example.entitycom.entity.member.Members;
import com.example.memberssecurity.member.service.MemberService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JWTUtils jwtUtils;
    private final MemberService memberService;
    // - 서버 템플릿이면 "http://localhost:8086/auth/success" 같은 페이지

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        log.debug("Authentication success: {}", authentication);
        if (!(authentication instanceof OAuth2AuthenticationToken oauthToken)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid authentication type");
            return;
        }

        SocialUserInfo userInfo = getSocialUserInfo(oauthToken);
        Members member = memberService.upsertOAuthUser(userInfo);

        String accessToken = jwtUtils.createToken(member.getMemberKey(), member.getRole().name(), 60 * 60 * 1000L);
        // Electron 앱이 인식할 수 있도록 URL 뒤에 토큰을 붙여서 보냄
        String targetUrl = "jo-gpt://auth-success?token=" + accessToken;
        log.debug("Redirecting to Electron app with token: {}", accessToken);

        Cookie cookie = new Cookie("ACCESS_TOKEN", accessToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(false);

        cookie.setPath("/");
        cookie.setMaxAge(60 * 60);
        response.addCookie(cookie);

log.debug("Redirecting to Electron app with token: {}", accessToken);
        response.sendRedirect(targetUrl);
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
