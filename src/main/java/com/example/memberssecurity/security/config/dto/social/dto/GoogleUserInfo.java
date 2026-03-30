package com.example.memberssecurity.security.config.dto.social.dto;

import java.util.Map;

public class GoogleUserInfo implements SocialUserInfo{

    private final Map<String, Object> attributes;

    public GoogleUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getProviderId() {
        return attributes.get("sub").toString();
    }

    @Override
    public String getName() {
        return attributes.get("name").toString();
    }

    @Override
    public String getEmail() {
        return attributes.get("email").toString();
    }

    @Override
    public String getImageUrl() {
        return attributes.get("picture").toString();
    }

    @Override
    public String getProvider() {
        return "google";
    }
}
