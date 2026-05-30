package com.example.memberssecurity.member.restController;

import com.example.memberssecurity.member.service.ConnectedAccountsService;
import com.example.memberssecurity.security.config.dto.CustomUserDetails;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequiredArgsConstructor
@RequestMapping("/connect")
public class ConnectedAccountsController {

    private final ConnectedAccountsService connectedAccountsService;

    private Long getMemberKey() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof CustomUserDetails userDetails) {
            return userDetails.getMemberId();
        }
        throw new RuntimeException("로그인 정보가 없습니다.");
    }

    // Google 계정 연결 시작
    @GetMapping("/google")
    public void connectGoogle(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Long memberKey = getMemberKey();

        // ✅ 세션 대신 쿠키에 저장 (STATELESS 환경에서도 유지됨!)
        Cookie cookie = new Cookie("connectingMemberKey", String.valueOf(memberKey));
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(180); // 3분
        response.addCookie(cookie);

        response.sendRedirect("/oauth2/authorization/google-connect");
    }

    @GetMapping("/list")
    public ResponseEntity<?> getConnectedAccounts() {
        Long memberKey = getMemberKey();
        return ResponseEntity.ok(connectedAccountsService.getList(memberKey));
    }

    @DeleteMapping("/{accountKey}")
    public ResponseEntity<?> disconnect(@PathVariable Long accountKey) {
        connectedAccountsService.disconnect(accountKey);
        return ResponseEntity.ok().build();
    }
}
