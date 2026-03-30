package com.example.memberssecurity.security.config.jwt;

import com.example.memberssecurity.security.config.dto.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtils jwtUtils;
    public LoginFilter(AuthenticationManager authenticationManager,
                       JWTUtils jwtUtils) {
        setFilterProcessesUrl("/api/auth/login");
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
    }
    /*
    * 로그인 요청 시 사용자 인증 처리
    * */

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String memberId = request.getParameter("memberId");
        String password = request.getParameter("password");

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(memberId, password);

        return authenticationManager.authenticate(authenticationToken);
    }

    /*
    * 로그인 성공 시 JWT 토큰 발급
    * */

    @Override
    protected  void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication auth) throws IOException {
        CustomUserDetails customUserDetails = (CustomUserDetails) auth.getPrincipal();

        assert customUserDetails != null;
        Long memberId = customUserDetails.getMemberId();

        // 사용자 역할 (Role) 조회
        Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority grantedAuthority = iterator.next();

        String role = grantedAuthority.getAuthority();
        String token = jwtUtils.createToken(memberId, role, 60 * 60 * 1000L); //1시간 유효 토큰 생성

        // JWT를 쿠키에 저장
        Cookie cookie = new Cookie("ACCESS_TOKEN", token);
        cookie.setHttpOnly(true);
        cookie.setSecure(false); // 로컬 테스트용 (운영 시 true 권장)
        cookie.setPath("/");
        cookie.setMaxAge(60 * 60);
        response.addCookie(cookie);

        response.addHeader("Authorization", "Bearer " + token); //JWT 를 Authorization 헤더에 추가
        // ===== 여기부터가 중요 =====
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        String jsonResponse = """
        {
          "message": "로그인 성공",
          "memberId": "%s",
          "role": "%s",
          "token": "%s"
        }
        """.formatted(memberId, role, token);

        response.getWriter().write(jsonResponse);
    }

    /*
    * 로그인 실패 시 401 응답 반환
    * */

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws AuthenticationException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401 Unauthorized 응답
    }
}
