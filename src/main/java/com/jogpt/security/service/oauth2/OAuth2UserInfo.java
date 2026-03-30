package com.jogpt.security.service.oauth2;

import java.util.Map;

/**
 * OAuth2 제공자별 사용자 정보 추상 클래스
 */
public abstract class OAuth2UserInfo {

    protected final Map<String, Object> attributes;

    protected OAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    public abstract String getId();

    public abstract String getName();

    public abstract String getEmail();

    public abstract String getProfileImageUrl();

    public Map<String, Object> getAttributes() {
        return attributes;
    }
}
