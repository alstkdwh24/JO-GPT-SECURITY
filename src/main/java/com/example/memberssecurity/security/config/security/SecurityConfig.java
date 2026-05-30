package com.example.memberssecurity.security.config.security;

import com.example.entitycom.entity.connect.ConnectedAccounts;
import com.example.memberssecurity.security.config.dto.CustomOAuth2UserService;
import com.example.memberssecurity.security.config.filter.ClientTypeFilter;
import com.example.memberssecurity.security.config.handler.OAuth2LoginSuccessHandler;
import com.example.memberssecurity.security.config.jwt.JWTFilter;
import com.example.memberssecurity.security.config.jwt.JWTUtils;
import com.example.memberssecurity.security.config.jwt.LoginFilter;
import com.example.memberssecurity.security.config.repository.HttpCookieOAuth2AuthorizationRequestRepository;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
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
    @Value("${spring.memberSecurity.url}")
    private String memberSecurityUrl;

    @Value("${spring.joGptProgram.url}")
    private String joGptProgramUrl;

    @Value("${spring.frontend.url}")
    private String frontendUrl;

    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        return request -> {
            CorsConfiguration corsConfiguration = new CorsConfiguration();

            corsConfiguration.setAllowedOrigins(Arrays.asList(
                    memberSecurityUrl,
                    joGptProgramUrl,
                    frontendUrl,
                    "http://agentcloudllm.me:5173",
                    "https://agentcloudllm.me"));

            corsConfiguration.setAllowedMethods(Collections.singletonList("*"));

            corsConfiguration.setAllowedHeaders(
                    Arrays.asList("Authorization", "Content-Type", "Cache-Control", "X-Requested-With", "X-Model",
                            "X-Custom-Prompt"));

            corsConfiguration.setAllowCredentials(true);
            corsConfiguration.setExposedHeaders(Arrays.asList("Authorization", "Set-Cookie"));
            corsConfiguration.setMaxAge(3600L);
            return corsConfiguration;
        };
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, CustomOAuth2UserService customOAuth2UserService,
            OAuth2LoginSuccessHandler successHandler, ClientRegistrationRepository clientRegistrationRepository)
            throws Exception {

        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))

                .authorizeHttpRequests(auth -> auth
                        .dispatcherTypeMatchers(DispatcherType.ASYNC).permitAll()
                        .requestMatchers("/login/**", "/login/oauth2/**", "/", "/signUp", "/home/**", "/css/**",
                                "/js/**", "/image/**", "/oauth2/**", "/joGpt/**", "/oauth2/authorization/**",
                                "/favicon.ico", "/error", "/auth/**", "/connect/**") // ← /connect/** 추가!
                        .permitAll()
                        .requestMatchers("/JO_GPT_PROGRAM/**", "/contents/**", "/gptApi/**").hasAuthority("ROLE_USER")
                        .requestMatchers("/admin").hasAuthority("ROLE_ADMIN")
                        .anyRequest().authenticated())

                .addFilterBefore(new ClientTypeFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JWTFilter(jwtUtils), UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(new LoginFilter(authenticationManager(), jwtUtils), JWTFilter.class)

                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .logout(logout -> logout.logoutUrl("/login/logout")
                        .addLogoutHandler((request, response, authentication) -> {
                            jwtUtils.invalidateToken(authentication);
                            Cookie accessTokenCookie = new Cookie("ACCESS_TOKEN", null);
                            accessTokenCookie.setHttpOnly(true);
                            accessTokenCookie.setSecure(true);
                            accessTokenCookie.setPath("/");
                            accessTokenCookie.setMaxAge(0);
                            response.addCookie(accessTokenCookie);
                        })
                        .logoutSuccessHandler(
                                (request, response, authentication) -> response.setStatus(HttpServletResponse.SC_OK)))
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(auth -> auth
                                .authorizationRequestRepository(new HttpCookieOAuth2AuthorizationRequestRepository())
                                .authorizationRequestResolver(
                                        authorizationRequestResolver(clientRegistrationRepository)))
                        .userInfoEndpoint(userInfo -> userInfo.userService(customOAuth2UserService))
                        .successHandler(successHandler)
                        .failureHandler((request, response, exception) -> {
                            String errorMessage = exception.getMessage();
                            String encodedMessage = java.net.URLEncoder.encode(errorMessage,
                                    java.nio.charset.StandardCharsets.UTF_8);
                            response.sendRedirect("http://localhost:5173?error=" + encodedMessage);
                        }));
        return http.build();
    }

    private OAuth2AuthorizationRequestResolver authorizationRequestResolver(
            org.springframework.security.oauth2.client.registration.ClientRegistrationRepository clientRegistrationRepository) {
        DefaultOAuth2AuthorizationRequestResolver authorizationRequestResolver = new DefaultOAuth2AuthorizationRequestResolver(
                clientRegistrationRepository, "/oauth2/authorization");

        authorizationRequestResolver.setAuthorizationRequestCustomizer(builder -> {
            String registrationId = (String) builder.build().getAttributes()
                    .get(org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.REGISTRATION_ID);

            builder.additionalParameters(params -> {
                System.out.println(">>> OAuth2 로그인 시도 중! 서비스: " + registrationId);
                if ("naver".equalsIgnoreCase(registrationId)) {
                    params.remove("auth_type");
                } else {
                    params.put("prompt", "select_account");
                }
            });
        });
        return authorizationRequestResolver;
    }
}
