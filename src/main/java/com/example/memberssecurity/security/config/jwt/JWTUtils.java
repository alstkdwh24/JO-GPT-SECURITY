package com.example.memberssecurity.security.config.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.example.entitycom.enums.Role;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class JWTUtils {

    private final SecretKey secretKey;

    private final RedisTemplate<String, String> redisTemplate;

    private static final long REFRESH_EXPIRATION = 1000L * 60 * 60; // 1시간

    /*
     * 생성자에서 application.properties에 저장된 SecretKey 값을 가져와 설정
     */
    public JWTUtils(
            @Value("${spring.jwt.secret}") String secret,
            @Qualifier("redisTemplate") RedisTemplate<String, String> redisTemplate) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));

        this.redisTemplate = redisTemplate;
    }

    // 리프레시 토큰 생성 메서드
    public String createRefreshToken(Long memberKey) {
        return Jwts.builder()
                .subject(String.valueOf(memberKey))
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + REFRESH_EXPIRATION))
                .signWith(secretKey)
                .compact();
    }

    /* 토큰 검증 메서드 */

    public void validate(String token) {
        Jwts.parser()
                .verifyWith(secretKey) // SecretKey 사용 권장
                .build()
                .parseSignedClaims(token);

    }
    /*
     * JWT에서 memberId 추출
     */

    public Long getUsername(String token) {

        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("memberId", Long.class);
    }

    /*
     * JWT에서 Role(권한) 추출
     */
    public String getRole(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("role", String.class);
    }

    /*
     * JWT 만료 여부 확인
     */

    public Boolean isTokenExpired(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration()
                .before(new Date());
    }

    /*
     * JWT 생성 메서드
     * - memberId, role(권한), 만료 시간 (expiredMs) 등을 포함한 JWT 발급
     */

    public String createToken(Long memberId, Role role, Long expiredMs) {

        log.debug("카카오 토큰 생성 단계{}", memberId);
        return Jwts.builder()
                .claim("memberId", memberId)
                .claim("role", role.name())
                .issuedAt(new Date(System.currentTimeMillis())) // 발급시간
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                .signWith(secretKey) // 비밀키를 사용하여 서명

                .compact();

    }

    public void invalidateToken(Authentication authentication) {
        if (authentication == null || authentication.getCredentials() == null) {
            return;
        }
        String token = authentication.getCredentials().toString();

        try {
            // 토큰의 남은 유효 시간을 계산
            Date expiration = Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload()
                    .getExpiration();

            long remainingTime = expiration.getTime() - System.currentTimeMillis();

            if (remainingTime > 0) {
                redisTemplate.opsForValue().set(token, "logout", remainingTime, TimeUnit.MILLISECONDS);
                // 위와 같이 Redis에 토큰을 저장하고, JWTFilter에서 이 토큰이 Redis에 있는지 확인해야 합니다.
                log.info("토큰 무효화 처리 시도 (남은 시간: {}ms)", remainingTime);
            }
        } catch (Exception e) {
            log.error("토큰 파싱 중 오류 발생: {}", e.getMessage());
        }
    }

    /* Redis 블랙리스트 */
    public boolean isBlacklisted(String token) {
        return redisTemplate.opsForValue().get(token) != null;
    }
}
