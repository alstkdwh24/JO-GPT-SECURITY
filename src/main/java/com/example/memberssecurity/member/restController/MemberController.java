package com.example.memberssecurity.member.restController;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.memberssecurity.member.dto.request.SignUpDto;
import com.example.memberssecurity.member.service.MemberService;
import com.example.memberssecurity.security.config.dto.CustomUserDetails;
import com.example.memberssecurity.security.config.jwt.JWTUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/login")
@Slf4j
public class MemberController {

    @Value("${spring.security.oauth2.client.registration.kakao.client-id}")
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
    public void logout(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        jWTUtils.invalidateToken(authentication);

        if (authentication != null) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }

        // @RestController에서는 "redirect:..." 문자열을 반환하면 리다이렉트되지 않음
        // 직접 response를 사용하여 리다이렉트 시킴
        response.sendRedirect("http://localhost:8086/home/GPT-Home");
    }

}
