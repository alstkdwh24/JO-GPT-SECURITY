package com.jogpt.security.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class JwtTokenProviderTest {

    private JwtTokenProvider jwtTokenProvider;

    @BeforeEach
    void setUp() {
        jwtTokenProvider = new JwtTokenProvider(
                "test-secret-key-must-be-at-least-32-characters-long",
                3600000L,
                1209600000L
        );
    }

    @Test
    void 액세스_토큰_생성_및_검증() {
        String token = jwtTokenProvider.generateAccessToken(1L, "test@example.com");

        assertThat(token).isNotBlank();
        assertThat(jwtTokenProvider.validateToken(token)).isTrue();
    }

    @Test
    void 토큰에서_사용자ID_추출() {
        String token = jwtTokenProvider.generateAccessToken(42L, "test@example.com");

        Long userId = jwtTokenProvider.getUserIdFromToken(token);

        assertThat(userId).isEqualTo(42L);
    }

    @Test
    void 토큰에서_이메일_추출() {
        String token = jwtTokenProvider.generateAccessToken(1L, "test@example.com");

        String email = jwtTokenProvider.getEmailFromToken(token);

        assertThat(email).isEqualTo("test@example.com");
    }

    @Test
    void 잘못된_토큰은_유효하지_않음() {
        assertThat(jwtTokenProvider.validateToken("invalid.token.value")).isFalse();
    }

    @Test
    void 빈_토큰은_유효하지_않음() {
        assertThat(jwtTokenProvider.validateToken("")).isFalse();
    }

    @Test
    void 리프레시_토큰_생성_및_검증() {
        String token = jwtTokenProvider.generateRefreshToken(1L);

        assertThat(token).isNotBlank();
        assertThat(jwtTokenProvider.validateToken(token)).isTrue();
        assertThat(jwtTokenProvider.getUserIdFromToken(token)).isEqualTo(1L);
    }
}
