package com.example.memberssecurity.security.config.dto.social.dto;

public interface SocialUserInfo {
    String getProviderId(); // 소셜에서 주는 고유 ID
    String getName();
    String getEmail();
    String getImageUrl();
    String getProvider();
}
