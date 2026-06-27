package com.example.memberssecurity.member.restController;

import com.example.entitycom.enums.Role;
import com.example.memberssecurity.member.dto.UserInfoDto;
import com.example.memberssecurity.security.config.jwt.JWTUtils;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
@Slf4j
@RestController
@RequestMapping("/auth")
public class AuthValidateController {

    private final JWTUtils jwtUtils;

    public AuthValidateController(JWTUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @GetMapping("/validate")
    public ResponseEntity<UserInfoDto> getMethodName(@RequestHeader(value = "Authorization", required = false) String token, HttpServletRequest request, HttpServletResponse response) {
        if (token == null || token.isBlank()) {
            return ResponseEntity.status(401).build();
        }

        String rawToken = token.replace("Bearer ", "");

        if (rawToken.isBlank()) {
            return ResponseEntity.status(401).build();
        }

        if (jwtUtils.isTokenExpired(rawToken)) {
            log.debug("token: {}", token);

            String refreshToken = null;
            if (request.getCookies() != null) {
                for (Cookie cookie : request.getCookies()) {
                    if ("REFRESH_TOKEN".equals(cookie.getName())) {
                        refreshToken = cookie.getValue();
                        break;
                    }
                }
            }

            // Refresh Token 없거나 만료됐으면 재로그인
            if (refreshToken == null || jwtUtils.isTokenExpired(refreshToken)) {
                return ResponseEntity.status(401).build();
            }
            // Refresh Token 유효 → 새 Access Token 발급
            Long memberKey = jwtUtils.getUsername(refreshToken);
            String role = jwtUtils.getRole(refreshToken);
            String newAccessToken = jwtUtils.createToken(
                    memberKey, Role.valueOf(role), 1000L * 60 * 60 *3
            );

            // 새 Access Token 쿠키에 저장
            Cookie accessCookie = new Cookie("ACCESS_TOKEN", newAccessToken);
            accessCookie.setHttpOnly(true);
            accessCookie.setSecure(true);
            accessCookie.setPath("/");
            accessCookie.setMaxAge(60 * 60 * 24 * 7);
            response.addCookie(accessCookie);
            response.setHeader("Authorization", "Bearer " + newAccessToken);


            return ResponseEntity.ok(buildUserInfoDto(memberKey, role)); // ← 메서드 호출!
        }
        // 블랙리스트 확인
        if (jwtUtils.isBlacklisted(rawToken)) {
            return ResponseEntity.status(401).build();
        }

        Long memberKey = jwtUtils.getUsername(rawToken);
        String role = jwtUtils.getRole(rawToken);

        return ResponseEntity.ok(buildUserInfoDto(memberKey, role)); // ← 메서드 호출!

    }

    // 중복 제거용 private 메서드
    private UserInfoDto buildUserInfoDto(Long memberKey, String role) {
        return UserInfoDto.builder()
                .memberId(String.valueOf(memberKey))
                .role(Role.valueOf(role))
                .build();
    }
}
