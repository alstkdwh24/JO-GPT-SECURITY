package com.example.memberssecurity.member.restController;

import com.example.memberssecurity.member.dto.request.SignUpDto;
import com.example.memberssecurity.member.service.MemberService;
import com.example.memberssecurity.security.config.dto.CustomUserDetails;
import com.example.memberssecurity.security.config.jwt.JWTUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/login")
@Slf4j
public class MemberController {

    @Value("${spring.security.oauth2.client.registration.kakao.client_id}")
    private String kakaoClientId;

    private final MemberService memberService;
    private final JWTUtils jWTUtils;

    public MemberController(MemberService memberService, JWTUtils jWTUtils) {
        this.memberService = memberService;
        this.jWTUtils = jWTUtils;
    }

    @PostMapping("/signUp")
    public ResponseEntity<String> signUp(@RequestBody SignUpDto dto) {
        memberService.signUp(dto);
        return ResponseEntity.ok("success");
    }

    @GetMapping("/myInfo")
    public ResponseEntity<?> getMemberInfo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // 1. 인증 정보 및 익명 사용자 체크
        if (authentication == null || !authentication.isAuthenticated() ||
                "anonymousUser".equals(String.valueOf(authentication.getPrincipal()))) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("로그인이 필요합니다.");
        }
        // 사용자 정보를 가져오기 위한 객체 생성
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        // 사용자 ID 추출
        Long memberId = userDetails.getMemberId();

        return memberService.memberUserInfo(memberId)
                .<ResponseEntity<?>>map(ResponseEntity::ok).orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        jWTUtils.invalidateToken(authentication);
        if (authentication != null) {
            String provider = "";

            if (authentication instanceof OAuth2AuthenticationToken oauthToken) {
                provider = oauthToken.getAuthorizedClientRegistrationId();
            }   // 2. 일반 로그인(CustomUserDetails)인 경우 DB 연동 정보 확인 (필요 시)
            else if (authentication.getPrincipal() instanceof CustomUserDetails userDetails) {
                // MemberService 등을 통해 해당 사용자의 AuthProviders 정보를 조회하여 provider 확인 가능
                // provider = memberService.getProviderByMemberKey(userDetails.getMemberId());
            }

            new SecurityContextLogoutHandler().logout(request, response, authentication);

            // 현재 인증된 공급자 확인 (예시 logic)
            // GitHub 사용자인 경우
            if("kakao".equals(provider)) {
                return "\"redirect:https://kauth.kakao.com/oauth/logout?client_id=\"" + kakaoClientId + "\"&redirect_uri=http://localhost:8086/login/logout";
            }
            if ("github".equals(provider)) {
                log.debug("Logging out from GitHub");
                return "redirect:https://github.com/logout";
            }

            // 만약 GitHub 사용자라면 GitHub 로그아웃 페이지나 메인으로 리다이렉트
            return "redirect:/";
        }
        return "redirect:https://kauth.kakao.com/oauth/logout?client_id=" + kakaoClientId + "&redirect_uri=http://localhost:8086/login/logout";
    }

}
