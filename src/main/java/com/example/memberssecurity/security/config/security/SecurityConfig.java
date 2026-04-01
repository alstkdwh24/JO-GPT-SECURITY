package com.example.memberssecurity.security.config.security;


/*
 * Spring Security Config
 * */


import com.example.memberssecurity.security.config.dto.CustomOAuth2UserService;
import com.example.memberssecurity.security.config.handler.OAuth2LoginSuccessHandler;
import com.example.memberssecurity.security.config.jwt.JWTFilter;
import com.example.memberssecurity.security.config.jwt.JWTUtils;
import com.example.memberssecurity.security.config.jwt.LoginFilter;
import com.example.memberssecurity.security.config.repository.HttpCookieOAuth2AuthorizationRequestRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableMethodSecurity(securedEnabled = true)
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtils jwtUtils;
    private final CustomOAuth2UserService customOAuth2UserService;

    /*
     * Spring Security의 AuthenticationManager 를 빈으로 등록
     * - 로그인 시 사용자의 인증(Authentication)을 담당
     * */

    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /*
     * 비밀번호 암호화를 위한 BCryptPasswordEncoder 빈 등록
     * - 회원가입 시 비밀번호를 안전하게 암호화하는 역할
     * */

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /*
     * CORS 설정을 위한 Bean 등록
     * - 프론트엔드(React 등)에서 API 요청 시 CORS 문제 해결
     * */

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        return request -> {
            CorsConfiguration corsConfiguration = new CorsConfiguration();
            corsConfiguration.setAllowedOrigins(Arrays.asList(
                    "http://localhost:8086",
                    "jo-gpt://",               // Electron이 로컬 파일을 로드할 때 쓰는 프로토콜
                    "null"                   // 일부 환경에서 Electron이 보내는 값
            ));
            corsConfiguration.setAllowedMethods(Collections.singletonList("*")); // 모든 HTTP 메서드 허용
            corsConfiguration.setAllowCredentials(true);
            corsConfiguration.setAllowedHeaders(Collections.singletonList("*"));  //모든 헤더 허용
            corsConfiguration.setExposedHeaders(Collections.singletonList("Authorization")); // Authorization 헤더 노출
            corsConfiguration.setMaxAge(3600L);
            return corsConfiguration;

        };
    }

    /*
     * Spring Security 필터 체인 설정
     * - JWT 인증을 기반으로 한 보안 설정 적용
     * */

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, CustomOAuth2UserService customOAuth2UserService, OAuth2LoginSuccessHandler successHandler) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource())) //CORS 설정 적용
                .csrf(AbstractHttpConfigurer::disable) //JWT 사용 시 CSRF 보호 비활성화
                .formLogin(AbstractHttpConfigurer::disable) // 기본 로그인 창 비활성화 (JWT 사용)
                .httpBasic(AbstractHttpConfigurer::disable) //HTTP Basic 인증 비활성화
                .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login/**", "/login/oauth2/**", "/", "/signUp", "/home/**", "/css/**", "/js/**", "/image/**", "/oauth2/**", "/joGpt/**", "/oauth2/authorization/**", "/gptApi/**", "/favicon.ico", "/error").permitAll() // 로그인, 회원가입 등은 누구나 접근 가능
                        .requestMatchers("/admin").hasAuthority("ROLE_ADMIN")  // /admin 경로는 ADMIN 권한이 필요
                        .anyRequest().authenticated())  //그 외의 요청은 인증된 사용자만 접근 가능

                // JWT 필터 추가 (기존 UsernamePasswordAuthenticationFilter 이전에 실행)
                .addFilterBefore(new JWTFilter(jwtUtils), UsernamePasswordAuthenticationFilter.class)

                // 로그인 필터 추가 (JWTFilter 실행 후 JWT 발급 처리)
                .addFilterAfter(new LoginFilter(authenticationManager(), jwtUtils), JWTFilter.class)

                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) //IF_REQUIRED는 필요할 때만 세션을 생성한다는 것이다.
                .logout(logout -> logout.logoutUrl("/login/logout")
                        .addLogoutHandler((request, response, authentication) -> {jwtUtils.invalidateToken(authentication);
                            Cookie accessTokenCookie = new Cookie("ACCESS_TOKEN", null);
                            accessTokenCookie.setHttpOnly(true);
                            accessTokenCookie.setSecure(true);
                            accessTokenCookie.setPath("/");
                            accessTokenCookie.setMaxAge(0);
                            response.addCookie(accessTokenCookie);
                        })
                        .invalidateHttpSession(true)  //세션무효화
                        .clearAuthentication(true)   // 인증 정보 삭제
                        .deleteCookies("ACCESS_TOKEN", "JSESSIONID")

                        .logoutSuccessHandler((request, response, authentication) -> response.setStatus(HttpServletResponse.SC_OK)))
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(auth -> auth.authorizationRequestRepository(new HttpCookieOAuth2AuthorizationRequestRepository()))
                        .userInfoEndpoint(userInfo -> userInfo.userService(customOAuth2UserService))
                        .successHandler(successHandler)
                        .failureHandler((request, response, exception) -> {
                            // 인증 실패 시 에러 메시지를 포함하여 홈 화면으로 리다이렉트
                            String errorMessage = exception.getMessage();
                            String encodedMessage = java.net.URLEncoder.encode(errorMessage, java.nio.charset.StandardCharsets.UTF_8);
                            response.sendRedirect("/home/GPT-Home?error=" + encodedMessage);
                        }));
        return http.build();
    }
}
