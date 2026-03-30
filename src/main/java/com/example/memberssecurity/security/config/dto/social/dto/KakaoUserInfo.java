package com.example.memberssecurity.security.config.dto.social.dto;

import java.util.Map;

public class KakaoUserInfo implements SocialUserInfo {

    private final Map<String, Object> attributes;

    public KakaoUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getProviderId() {

        if (attributes.get("id") instanceof Number id) {
            return id.toString();
        }

        return null;// 또는 예외 처리
    }

    @Override
    public String getName() {


        if (attributes.get("kakao_account") instanceof Map<?, ?> kakaoAccount
                && kakaoAccount.get("profile") instanceof Map<?, ?> profile) {

            Object nickname = profile.get("nickname");
            return nickname != null ? nickname.toString() : null;
        }
        return null;
    }

    @Override
    public String getEmail() {
        if(attributes.get("kakao_account")  instanceof Map<?,?> kakaoAccount){

            Object email = kakaoAccount.get("email");

            return email !=null ? email.toString() : null;
        }
     return null;
    }

    @Override
    public String getImageUrl() {
        Object kakaoAccountObject = attributes.get("kakao_account");
        if(!(kakaoAccountObject instanceof Map <?,?> kakaoAccount)){
            return null;
        }
        Object profileObj = kakaoAccount.get("profile");

        if (!(profileObj instanceof Map<?, ?> profile)) {
            return null;
        }

        Object image = profile.get("profile_image_url"); // 원본
        if (image == null) image = profile.get("thumbnail_image_url"); // 대체

        return image != null ? image.toString() : null;
    }

    @Override
    public String getProvider() {
        return "kakao";
    }
}
