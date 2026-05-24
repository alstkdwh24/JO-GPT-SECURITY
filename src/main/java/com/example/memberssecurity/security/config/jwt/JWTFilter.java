package com.example.memberssecurity.security.config.jwt;

import com.example.entitycom.entity.member.Members;
import com.example.entitycom.enums.Role;
import com.example.memberssecurity.security.config.dto.CustomUserDetails;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtils jwtUtils;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        log.debug("Request URI: {}", request.getRequestURI());

        String token = resolveToken(request);
        String refreshToken = resolveRefreshToken(request);


        // 토큰이 없으면 다음 필터로 (permitAll 경로)
        if (token == null || token.isEmpty()) {
            filterChain.doFilter(request, response);
            return;
        }

        // JWT 기본 형식 가드
        if (token.chars().filter(ch -> ch == '.').count() != 2) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            jwtUtils.validate(token);

            // 블랙리스트 확인
            if (jwtUtils.isBlacklisted(token)) {
                writeErrorResponse(response, "{\"code\":\"BLACKLISTED\",\"message\":\"로그아웃된 토큰입니다.\"}");
                return;
            }

            Long memberId = jwtUtils.getUsername(token);
            String roleStr = jwtUtils.getRole(token);
            Role role = Role.valueOf(roleStr);

            setAuthentication(memberId, role);

        } catch (ExpiredJwtException e) {
            log.error("JWT 만료: {}", e.getMessage());

            // Refresh Token 으로 재발급 시도
            if (refreshToken != null && !refreshToken.isEmpty()) {
                try {
                    jwtUtils.validate(refreshToken);

                    Long memberKey = jwtUtils.getUsername(refreshToken);
                    String roleStr = jwtUtils.getRole(refreshToken);
                    Role role = Role.valueOf(roleStr);

                    // 새 Access Token 발급
                    String newAccessToken = jwtUtils.createToken(
                            memberKey, role, 1000L * 60 * 60
                    );

                    // 새 Access Token 쿠키 저장
                    Cookie accessCookie = new Cookie("ACCESS_TOKEN", newAccessToken);
                    accessCookie.setHttpOnly(true);
                    accessCookie.setSecure(true);
                    accessCookie.setPath("/");
                    accessCookie.setMaxAge(60 * 60);
                    response.addCookie(accessCookie);
                    response.setHeader("Authorization", "Bearer " + newAccessToken);


                    setAuthentication(memberKey, role);

                    filterChain.doFilter(request, response);
                    return;

                } catch (Exception ex) {
                    log.error("Refresh Token 검증 실패: {}", ex.getMessage());
                }
            }

            // Refresh Token 도 만료 또는 없음
            writeErrorResponse(response, "{\"code\":\"EXPIRED_TOKEN\",\"message\":\"토큰이 만료되었습니다.\"}");
            return;

        } catch (SignatureException e) {
            log.error("JWT 서명 오류: {}", e.getMessage());
            writeErrorResponse(response, "{\"code\":\"INVALID_SIGNATURE\",\"message\":\"토큰 서명이 유효하지 않습니다.\"}");
            return;

        } catch (MalformedJwtException e) {
            log.error("JWT 형식 오류: {}", e.getMessage());
            writeErrorResponse(response, "{\"code\":\"MALFORMED_TOKEN\",\"message\":\"토큰 형식이 올바르지 않습니다.\"}");
            return;

        } catch (Exception e) {
            log.error("JWT 검증 오류: {}", e.getMessage());
            writeErrorResponse(response, "{\"code\":\"INVALID_TOKEN\",\"message\":\"토큰이 유효하지 않습니다.\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private void setAuthentication(Long memberId, Role role) {
        Members members = Members.builder()
                .memberId(String.valueOf(memberId))
                .memberKey(memberId)
                .role(role)
                .build();

        CustomUserDetails customUserDetails = new CustomUserDetails(members);
        Authentication authentication = new UsernamePasswordAuthenticationToken(
            customUserDetails, null, customUserDetails.getAuthorities()
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private void writeErrorResponse(HttpServletResponse response, String message) throws IOException {
        if (response.isCommitted()) return;
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json; charset=UTF-8");
        response.getWriter().write(message);
    }

    private String resolveCookieToken(HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(cookieName)) {
                    String token = cookie.getValue();
                    return token == null ? null : token.trim();
                }
            }
        }
        return null;
    }

    private String resolveToken(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return authorization.substring(7).trim();
        }
        return resolveCookieToken(request, "ACCESS_TOKEN");

    }

    private String resolveRefreshToken(HttpServletRequest request) {
        return resolveCookieToken(request, "REFRESH_TOKEN");

    }
}
