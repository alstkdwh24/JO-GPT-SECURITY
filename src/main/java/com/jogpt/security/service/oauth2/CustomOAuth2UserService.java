package com.jogpt.security.service.oauth2;

import com.jogpt.security.domain.entity.AuthProvider;
import com.jogpt.security.domain.entity.Role;
import com.jogpt.security.domain.entity.User;
import com.jogpt.security.domain.repository.UserRepository;
import com.jogpt.security.exception.OAuth2AuthenticationProcessingException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.Map;

/**
 * OAuth2 로그인 처리 서비스
 * - 신규 사용자: 자동 회원가입
 * - 기존 사용자: 프로필 정보 업데이트
 */
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId().toUpperCase();
        AuthProvider provider;
        try {
            provider = AuthProvider.valueOf(registrationId);
        } catch (IllegalArgumentException e) {
            throw new OAuth2AuthenticationProcessingException(
                    "지원하지 않는 로그인 제공자입니다: " + registrationId);
        }

        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(
                provider, oAuth2User.getAttributes());

        if (!StringUtils.hasText(userInfo.getEmail())) {
            throw new OAuth2AuthenticationProcessingException(
                    "OAuth2 제공자로부터 이메일 정보를 가져올 수 없습니다.");
        }

        User user = userRepository.findByAuthProviderAndProviderId(provider, userInfo.getId())
                .map(existingUser -> existingUser.update(userInfo.getName(), userInfo.getProfileImageUrl()))
                .orElseGet(() -> registerNewUser(userInfo, provider));

        userRepository.save(user);

        return new OAuth2UserPrincipal(user, oAuth2User.getAttributes());
    }

    private User registerNewUser(OAuth2UserInfo userInfo, AuthProvider provider) {
        // 같은 이메일로 다른 제공자 계정이 이미 존재하는 경우
        userRepository.findByEmail(userInfo.getEmail()).ifPresent(existing -> {
            throw new OAuth2AuthenticationProcessingException(
                    String.format("'%s' 이메일은 이미 %s 계정으로 가입되어 있습니다. 해당 계정으로 로그인해 주세요.",
                            userInfo.getEmail(), existing.getAuthProvider().name()));
        });

        return User.builder()
                .email(userInfo.getEmail())
                .name(userInfo.getName())
                .profileImageUrl(userInfo.getProfileImageUrl())
                .authProvider(provider)
                .providerId(userInfo.getId())
                .role(Role.USER)
                .build();
    }
}
