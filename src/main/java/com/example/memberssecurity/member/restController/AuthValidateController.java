package com.example.memberssecurity.member.restController;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.entitycom.enums.Role;
import com.example.memberssecurity.member.dto.UserInfoDto;
import com.example.memberssecurity.security.config.jwt.JWTUtils;

@RestController
@RequestMapping("/auth")
public class AuthValidateController {

    private final JWTUtils jwtUtils;

    public AuthValidateController(JWTUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @GetMapping("/validate")
    public ResponseEntity<UserInfoDto> getMethodName(@RequestHeader("Authorization") String token) {

        // 토큰 검증 후 유저 정보 반환
        // Bearer 제거
        String rawToken = token.replace("Bearer ", "");

        // 만료 확인
        if (jwtUtils.isTokenExpired(rawToken) || jwtUtils.isBlacklisted(rawToken)) {
            return ResponseEntity.status(401).build();
        }

        // 토큰에서 정보 추출
        Long memberKey = jwtUtils.getUsername(rawToken);
        // 역할 추출
        String role = jwtUtils.getRole(rawToken);
        // memberKey를 사용하여 UserInfoDto 생성
        UserInfoDto userInfo = UserInfoDto.builder()
                .memberId(String.valueOf(memberKey))
                .role(Role.valueOf(role))
                .build();
        return ResponseEntity.ok(userInfo);
    }

}