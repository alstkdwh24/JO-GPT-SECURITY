package com.example.memberssecurity.security.config.dto.social.dto;

public interface SocialUserInfo {
    String getProviderId(); // 소셜에서 주는 고유 ID
    String getName();
    String getEmail();
    String getImageUrl();
    String getProvider();

    // 닉네임 설정 모달에서 기본 제안값으로 사용할 닉네임 (기본값: getName())
    default String getSuggestedNickname() {
        return getName();
    }
}
