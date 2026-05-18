package com.example.memberssecurity.security.config.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// OAuth2 로그인 시작 전에 client=electron 파라미터를 세션에 저장하는 필터
// OAuth2 인증 중간에 파라미터가 사라지기 때문에 세션에 미리 저장해둠
public class ClientTypeFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // /oauth2/authorization/** 요청일 때만 처리
        String uri = request.getRequestURI();
        if (uri.startsWith("/oauth2/authorization/")) {
            String client = request.getParameter("client");
            if ("electron".equals(client)) {
                // 세션에 저장 (OAuth2LoginSuccessHandler에서 꺼내서 사용)
                request.getSession().setAttribute("client", "electron");
            }
        }
        filterChain.doFilter(request, response);
    }
}
