package com.jogpt.security.domain.entity;

/**
 * 로그인 제공자 구분
 */
public enum AuthProvider {
    LOCAL,   // 자체 로그인
    GOOGLE,  // 구글
    NAVER,   // 네이버
    KAKAO    // 카카오
}
