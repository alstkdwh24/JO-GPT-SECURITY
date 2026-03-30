package com.jogpt.security.dto.response;

import lombok.Builder;
import lombok.Getter;

/**
 * 인증 응답 DTO (로그인/회원가입 성공 시 반환)
 */
@Getter
@Builder
public class AuthResponse {

    private String accessToken;
    private String refreshToken;
    private String tokenType;
    private UserInfo user;

    @Getter
    @Builder
    public static class UserInfo {
        private Long id;
        private String name;
        private String email;
        private String profileImageUrl;
        private String authProvider;
        private String role;
    }
}
