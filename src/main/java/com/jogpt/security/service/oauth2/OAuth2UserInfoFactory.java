package com.jogpt.security.service.oauth2;

import com.jogpt.security.domain.entity.AuthProvider;

import java.util.Map;

/**
 * 제공자에 따른 OAuth2UserInfo 팩토리
 */
public class OAuth2UserInfoFactory {

    private OAuth2UserInfoFactory() {}

    public static OAuth2UserInfo getOAuth2UserInfo(AuthProvider provider, Map<String, Object> attributes) {
        return switch (provider) {
            case GOOGLE -> new GoogleOAuth2UserInfo(attributes);
            case NAVER  -> new NaverOAuth2UserInfo(attributes);
            case KAKAO  -> new KakaoOAuth2UserInfo(attributes);
            default     -> throw new IllegalArgumentException("지원하지 않는 OAuth2 제공자입니다: " + provider);
        };
    }
}
