package com.example.memberssecurity.security.config.dto.social.dto;

import java.util.Map;

public class GithubUserInfo implements SocialUserInfo {
    private final Map<String, Object> attributes;

    public GithubUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }


    @Override
    public String getProviderId() {
        return attributes.get("id").toString(); // PK
    }

    @Override
    public String getName() {
        Object name = attributes.get("name");
        return name != null ? name.toString() : (String) attributes.get("login");   }

    @Override
    public String getEmail() {
        Object email = attributes.get("email");
        return email != null ? email.toString() : null;
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get("avatar_url");    }

    @Override
    public String getProvider() {
        return "github";
    }
}
