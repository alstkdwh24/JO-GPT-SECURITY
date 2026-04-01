package com.jogpt.security.service.auth;

import com.jogpt.security.domain.entity.AuthProvider;
import com.jogpt.security.domain.entity.RefreshToken;
import com.jogpt.security.domain.entity.Role;
import com.jogpt.security.domain.entity.User;
import com.jogpt.security.domain.repository.RefreshTokenRepository;
import com.jogpt.security.domain.repository.UserRepository;
import com.jogpt.security.dto.request.LoginRequest;
import com.jogpt.security.dto.request.SignUpRequest;
import com.jogpt.security.dto.request.TokenRefreshRequest;
import com.jogpt.security.dto.response.AuthResponse;
import com.jogpt.security.exception.BadRequestException;
import com.jogpt.security.exception.ResourceNotFoundException;
import com.jogpt.security.exception.TokenRefreshException;
import com.jogpt.security.util.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * 자체 로그인 인증 서비스
 */
@Service
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final long refreshTokenExpiration;

    /**
     * @param authenticationManager @Lazy 로 주입 - SecurityConfig → OAuth2SuccessHandler → AuthService →
     *                              AuthenticationManager(SecurityConfig) 순환 의존성을 방지하기 위해 지연 초기화 사용
     */
    public AuthService(UserRepository userRepository,
                       RefreshTokenRepository refreshTokenRepository,
                       PasswordEncoder passwordEncoder,
                       @Lazy AuthenticationManager authenticationManager,
                       JwtTokenProvider jwtTokenProvider,
                       @Value("${jwt.refresh-token-expiration}") long refreshTokenExpiration) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.refreshTokenExpiration = refreshTokenExpiration;
    }

    /** 자체 회원가입 */
    @Transactional
    public AuthResponse signUp(SignUpRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new BadRequestException("이미 사용 중인 이메일입니다: " + request.getEmail());
        }

        User user = User.builder()
                .name(request.getName())
                .email(request.getEmail())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .authProvider(AuthProvider.LOCAL)
                .role(Role.USER)
                .build();

        userRepository.save(user);

        return buildAuthResponse(user);
    }

    /** 자체 로그인 */
    @Transactional
    public AuthResponse login(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new ResourceNotFoundException("사용자를 찾을 수 없습니다."));

        return buildAuthResponse(user);
    }

    /** 리프레시 토큰으로 액세스 토큰 갱신 */
    @Transactional
    public AuthResponse refreshToken(TokenRefreshRequest request) {
        String requestToken = request.getRefreshToken();

        RefreshToken refreshToken = refreshTokenRepository.findByToken(requestToken)
                .orElseThrow(() -> new TokenRefreshException("리프레시 토큰을 찾을 수 없습니다."));

        if (refreshToken.isExpired()) {
            refreshTokenRepository.delete(refreshToken);
            throw new TokenRefreshException("리프레시 토큰이 만료되었습니다. 다시 로그인해 주세요.");
        }

        User user = refreshToken.getUser();
        String newAccessToken = jwtTokenProvider.generateAccessToken(user.getId(), user.getEmail());

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(requestToken)
                .tokenType("Bearer")
                .user(toUserInfo(user))
                .build();
    }

    /** 로그아웃 - 리프레시 토큰 삭제 */
    @Transactional
    public void logout(String refreshToken) {
        refreshTokenRepository.deleteByToken(refreshToken);
    }

    /** 인증 응답 빌드 (토큰 생성 + 사용자 정보) */
    public AuthResponse buildAuthResponse(User user) {
        String accessToken = jwtTokenProvider.generateAccessToken(user.getId(), user.getEmail());
        String refreshTokenValue = jwtTokenProvider.generateRefreshToken(user.getId());

        // 기존 리프레시 토큰 삭제 후 새로 저장
        refreshTokenRepository.deleteByUser(user);

        RefreshToken refreshToken = RefreshToken.builder()
                .token(refreshTokenValue)
                .user(user)
                .expiresAt(LocalDateTime.now().plusSeconds(refreshTokenExpiration / 1000))
                .build();
        refreshTokenRepository.save(refreshToken);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshTokenValue)
                .tokenType("Bearer")
                .user(toUserInfo(user))
                .build();
    }

    private AuthResponse.UserInfo toUserInfo(User user) {
        return AuthResponse.UserInfo.builder()
                .id(user.getId())
                .name(user.getName())
                .email(user.getEmail())
                .profileImageUrl(user.getProfileImageUrl())
                .authProvider(user.getAuthProvider().name())
                .role(user.getRole().name())
                .build();
    }
}
