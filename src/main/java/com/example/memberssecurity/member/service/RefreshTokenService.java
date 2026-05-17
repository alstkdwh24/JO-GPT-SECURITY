package com.example.memberssecurity.member.service;

import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.springframework.stereotype.Service;

import com.example.entitycom.entity.member.Members;
import com.example.memberssecurity.member.repository.jpa.MemberRepository;
import com.example.memberssecurity.security.config.jwt.JWTUtils;
import com.example.memberssecurity.security.config.restTemplate.RedisTemplateConfig;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final JWTUtils jwtUtils;

    private final RedisTemplateConfig redisTemplateConfig;
    private static final long EXPIRE_MS = 1000L * 60 * 60 * 24 * 7; // 7일
    private final MemberRepository memberRepository;

    public void saveRefreshToken(Long memberKey, String refreshToken) {
        redisTemplateConfig.opsForValue().set("refresh_token:" + memberKey, refreshToken, EXPIRE_MS,
                TimeUnit.MILLISECONDS);
    }

    public boolean validate(Long memberKey, String refreshToken) {
        String storedToken = redisTemplateConfig.opsForValue().get("refresh_token:" + memberKey);
        return refreshToken.equals(storedToken);
    }

    public void delete(Long memberKey) {
        redisTemplateConfig.delete("refresh_token:" + memberKey);
    }

    public String refreshTokenService(HttpServletRequest request) {
        String refresh = Arrays.stream(Optional.ofNullable(request.getCookies()).orElse(new Cookie[0]))
                .filter(cookie -> "refresh_token".equals(cookie.getName()))
                .findFirst()
                .map(Cookie::getValue)
                .orElse(null);
        if (refresh == null)
            return null;

        Long memberKey = jwtUtils.getUsername(refresh);
        Members member = memberRepository.findById(memberKey)
                .orElseThrow(() -> new RuntimeException("회원 정보가 존재하지 않습니다."));

        // Redis에 저장된 토큰과 비교 검증
        if (!validate(memberKey, refresh))
            return null;

        // 기존 토큰 삭제 후 새 토큰 발급 (token rotation)
        delete(memberKey);
        String newAccessToken = jwtUtils.createToken(memberKey, member.getRole(), 60 * 60 * 1000L);

        return newAccessToken;
    }

}
