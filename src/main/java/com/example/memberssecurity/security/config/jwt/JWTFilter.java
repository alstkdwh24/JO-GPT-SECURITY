package com.example.memberssecurity.security.config.jwt;

import com.example.entitycom.entity.member.Members;
import com.example.entitycom.enums.Role;
import com.example.memberssecurity.security.config.dto.CustomUserDetails;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
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

        // resolveToken 메서드에서 Authorization 헤더 또는 쿠키에서 토큰을 추출합니다.
        String token = resolveToken(request);
        log.debug("Validating JWT token: {}", token);

        // [중요] 토큰이 없으면 그냥 다음 필터로 넘깁니다. (permitAll 경로를 위해)
        if (token == null || token.isEmpty()) {
            filterChain.doFilter(request, response);
            return;
        }

        if (!isCompactJwt(token)) {
            filterChain.doFilter(request, response);
            return;
        }

        if ((token == null || token.isEmpty()) && request.getCookies() != null) {
            for (jakarta.servlet.http.Cookie cookie : request.getCookies()) {
                if ("ACCESS_TOKEN".equals(cookie.getName())) {
                    token = cookie.getValue();
                    if (token != null)
                        token = token.trim();
                    break;
                }
            }
        }

        if (token == null || token.isEmpty()) {
            filterChain.doFilter(request, response);
            return;
        }

        // JWT 기본 형식 가드: header.payload.signature
        if (token.chars().filter(ch -> ch == '.').count() != 2) {
            filterChain.doFilter(request, response); // 또는 401 응답
            return;
        }

        /* *//* 토큰 만료 서명 검증 */
        try {
            jwtUtils.validate(token); // 여기서 서명/만료 검증 수행
            // 블랙리스트 확인 추가
            if (jwtUtils.isBlacklisted(token)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("로그아웃된 토큰입니다.");
                return;
            }

            Long memberId = jwtUtils.getUsername(token);
            String roleStr = jwtUtils.getRole(token);
            Role role = Role.valueOf(roleStr);

            Members members = Members.builder()
                    .memberId("1`2u019481209834198023")
                    .memberKey(memberId)
                    .role(role)
                    .build();

            CustomUserDetails customUserDetails = new CustomUserDetails(members);
            Authentication authentication = new UsernamePasswordAuthenticationToken(customUserDetails, null,
                    customUserDetails.getAuthorities());

            if (authentication != null) {

                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.info("JWT auth user={}, authorities={}",
                        authentication.getName(),
                        authentication.getAuthorities());
            }

            // SecurityContext에 인증 정보 저장 (STATELESS 모드)
            SecurityContextHolder.getContext().setAuthentication(authentication);
            filterChain.doFilter(request, response);

            /*
             * JWT의 세 번째 부분인 **서명**가 서버가 가지고 있는 비밀키로 검증했을때 일치하지 않는 경우 발생합니다.
             * MalformedJwtException JWT의 구조 자체가 올바르지 않을 때 발생합니다. JWT는 원래
             * Header.Payload;Signature 형식을 가져야 하는데
             * 이 형식을 벋어난 경우
             */
        } catch (ExpiredJwtException e) {
            log.error("JWT expired: {}", e.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setCharacterEncoding("UTF-8");
            response.setContentType("application/json; charset=UTF-8");
            response.getWriter().write("{\"code\":\"EXPIRED_TOKEN\",\"message\":\"토큰이 만료되었습니다.\"}");
            return;

        } catch (SignatureException e) {
            log.error("JWT invalid signature: {}", e.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setCharacterEncoding("UTF-8");
            response.setContentType("application/json; charset=UTF-8");
            response.getWriter().write("{\"code\":\"INVALID_SIGNATURE\",\"message\":\"토큰 서명이 유효하지 않습니다.\"}");
            return;

        } catch (MalformedJwtException e) {
            log.error("JWT malformed: {}", e.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setCharacterEncoding("UTF-8");
            response.setContentType("application/json; charset=UTF-8");
            response.getWriter().write("{\"code\":\"MALFORMED_TOKEN\",\"message\":\"토큰 형식이 올바르지 않습니다.\"}");
            return;
        } catch (Exception e) {
            log.error("JWT validation error: {}", e.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("토큰이 만료되었습니다.");
            return;
        }

    }

    private String resolveToken(HttpServletRequest request) {
        log.debug("Auth Header: {}", request.getHeader("Authorization"));
        String authorization = request.getHeader("Authorization");

        if (authorization != null && authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return authorization.substring(7).trim();
        }

        if (request.getCookies() != null) {
            for (jakarta.servlet.http.Cookie cookie : request.getCookies()) {
                if ("ACCESS_TOKEN".equals(cookie.getName())) {
                    String token = cookie.getValue();
                    return token == null ? null : token.trim();
                }
            }
        }

        return null;
    }

    // jwt 토큰이 기본 형식인 header.payload.signature인지 간단히 체크하는 메서드
    private boolean isCompactJwt(String token) {
        return token.chars().filter(ch -> ch == '.').count() == 2;
    }
}
