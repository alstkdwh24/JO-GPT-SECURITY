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
        log.debug("Generated JWT token: {}", member);

        // 1시간 유효 토큰 생성
        String accessToken = jwtUtils.createToken(member.getMemberKey(), member.getRole(), 60 * 60 * 1000L);
        String targetUrl = "jo-gpt://auth-success?token=" + accessToken;

        // 1. 쿠키 설정 (기존 로직 유지)
        Cookie cookie = new Cookie("ACCESS_TOKEN", accessToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true); // HTTPS 환경에서는 true로 변경 필요
        cookie.setPath("/");
        cookie.setMaxAge(60 * 60);
        response.addCookie(cookie);

        // 2. [개선] 직접 HTML 작성 대신 템플릿 페이지로 리다이렉트
        // 브라우저가 커스텀 프로토콜을 차단하는 경우를 대비하여 토큰을 포함해 템플릿 페이지로 보냅니다.
        response.sendRedirect("/home/GPT-Home?token=" + accessToken);

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
