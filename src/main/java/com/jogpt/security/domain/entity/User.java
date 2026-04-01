package com.jogpt.security.domain.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

/**
 * 사용자 엔티티 - 자체 로그인 및 SNS 로그인 모두 지원
 */
@Entity
@Table(name = "users")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@EntityListeners(AuditingEntityListener.class)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(name = "password_hash")
    private String passwordHash;

    @Column(nullable = false)
    private String name;

    private String profileImageUrl;

    /** 로그인 제공자 (local, google, naver, kakao) */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuthProvider authProvider;

    /** OAuth2 제공자에서 받은 고유 ID */
    private String providerId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(nullable = false)
    private LocalDateTime updatedAt;

    @Builder
    public User(String email, String passwordHash, String name,
                String profileImageUrl, AuthProvider authProvider,
                String providerId, Role role) {
        this.email = email;
        this.passwordHash = passwordHash;
        this.name = name;
        this.profileImageUrl = profileImageUrl;
        this.authProvider = authProvider;
        this.providerId = providerId;
        this.role = role != null ? role : Role.USER;
    }

    /** 프로필 정보 업데이트 (SNS 재로그인 시 동기화) */
    public User update(String name, String profileImageUrl) {
        this.name = name;
        this.profileImageUrl = profileImageUrl;
        return this;
    }

    /** 비밀번호 변경 */
    public void changePassword(String newPasswordHash) {
        this.passwordHash = newPasswordHash;
    }
}
