package com.example.memberssecurity.security.config.dto.social.dto;

import java.util.HashMap;
import java.util.Map;

public class NaverUserInfo implements SocialUserInfo{
    private final Map<String, Object> response;

    public NaverUserInfo(Map<String, Object> attributes) {
        Object resp = attributes.get("response");

        if(resp instanceof Map<?, ?> map){
            this.response = new HashMap<>();
            for(Map.Entry<?,?> e : map.entrySet()){
                if(e.getKey() instanceof String key){
                    this.response.put(key, e.getValue());
                }
            }
        }
        else{
            throw new IllegalArgumentException("Invalid Naver response structure");
        }

    }

    @Override
    public String getProviderId() {
        return getString("id");
    }

    @Override
    public String getName() {
        return getString("name");
    }

    @Override
    public String getEmail() {
        return getString("email");
    }
    @Override
    public String getImageUrl() {
        return getString("profile_image");
    }

    @Override
    public String getProvider() {
        return "naver";
    }

    private String getString(String key) {
        Object value = response.get(key);
        return value != null ? value.toString() : null;
    }
}
