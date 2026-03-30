package com.jogpt.security.handler;

import com.jogpt.security.config.AppProperties;
import com.jogpt.security.service.auth.AuthService;
import com.jogpt.security.service.oauth2.OAuth2UserPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

/**
 * OAuth2 로그인 성공 핸들러 - JWT 토큰을 쿼리 파라미터로 프론트엔드에 전달
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final AuthService authService;
    private final AppProperties appProperties;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        OAuth2UserPrincipal principal = (OAuth2UserPrincipal) authentication.getPrincipal();
        var authResponse = authService.buildAuthResponse(principal.getUser());

        String redirectUri = determineRedirectUri(request);

        String targetUrl = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("accessToken", authResponse.getAccessToken())
                .queryParam("refreshToken", authResponse.getRefreshToken())
                .build().toUriString();

        log.info("OAuth2 로그인 성공: {} -> {}", principal.getEmail(), redirectUri);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    private String determineRedirectUri(HttpServletRequest request) {
        String redirectUri = request.getParameter("redirect_uri");
        if (redirectUri != null && isAuthorizedRedirectUri(redirectUri)) {
            return redirectUri;
        }
        return appProperties.getOauth2().getAuthorizedRedirectUris().get(0);
    }

    private boolean isAuthorizedRedirectUri(String uri) {
        return appProperties.getOauth2().getAuthorizedRedirectUris().stream().anyMatch(uri::equals);
    }
}
