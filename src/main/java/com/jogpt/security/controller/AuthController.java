package com.jogpt.security.controller;

import com.jogpt.security.domain.entity.User;
import com.jogpt.security.domain.repository.UserRepository;
import com.jogpt.security.dto.request.LoginRequest;
import com.jogpt.security.dto.request.SignUpRequest;
import com.jogpt.security.dto.request.TokenRefreshRequest;
import com.jogpt.security.dto.response.ApiResponse;
import com.jogpt.security.dto.response.AuthResponse;
import com.jogpt.security.exception.ResourceNotFoundException;
import com.jogpt.security.service.auth.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

/**
 * 인증 API 컨트롤러
 * - POST /api/auth/signup    : 자체 회원가입
 * - POST /api/auth/login     : 자체 로그인
 * - POST /api/auth/refresh   : 액세스 토큰 갱신
 * - POST /api/auth/logout    : 로그아웃
 * - GET  /api/auth/me        : 내 정보 조회 (인증 필요)
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final UserRepository userRepository;

    /** 자체 회원가입 */
    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<AuthResponse>> signUp(@Valid @RequestBody SignUpRequest request) {
        AuthResponse response = authService.signUp(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("회원가입이 완료되었습니다.", response));
    }

    /** 자체 로그인 */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(@Valid @RequestBody LoginRequest request) {
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(ApiResponse.success("로그인에 성공하였습니다.", response));
    }

    /** 액세스 토큰 갱신 */
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AuthResponse>> refresh(@Valid @RequestBody TokenRefreshRequest request) {
        AuthResponse response = authService.refreshToken(request);
        return ResponseEntity.ok(ApiResponse.success("토큰이 갱신되었습니다.", response));
    }

    /** 로그아웃 */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(@Valid @RequestBody TokenRefreshRequest request) {
        authService.logout(request.getRefreshToken());
        return ResponseEntity.ok(ApiResponse.success("로그아웃 되었습니다.", null));
    }

    /** 내 정보 조회 */
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<AuthResponse.UserInfo>> me(
            @AuthenticationPrincipal UserDetails userDetails) {
        User user = userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다."));

        AuthResponse.UserInfo userInfo = AuthResponse.UserInfo.builder()
                .id(user.getId())
                .name(user.getName())
                .email(user.getEmail())
                .profileImageUrl(user.getProfileImageUrl())
                .authProvider(user.getAuthProvider().name())
                .role(user.getRole().name())
                .build();

        return ResponseEntity.ok(ApiResponse.success(userInfo));
    }
}
