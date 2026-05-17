package com.example.memberssecurity.member.restController;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.memberssecurity.member.service.RefreshTokenService;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/refreshToken")
public class RefreshController {

    private final RefreshTokenService refreshTokenService;

    @PostMapping("/login/refresh")
    public ResponseEntity<String> refreshToken(HttpServletRequest request) {

        String newAccessToken = refreshTokenService.refreshTokenService(request);
        if (newAccessToken == null) return ResponseEntity.status(401).build();
        return ResponseEntity.ok(newAccessToken);
    }
}
