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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.client.RestTemplate;

@RestController
@RequiredArgsConstructor
@RequestMapping("/connect")
public class ConnectedAccountsController {

    private final ConnectedAccountsService connectedAccountsService;

    @Value("${jo-gpt-program-url:http://localhost:8082}")
    private String joGptProgramUrl;

    private final RestTemplate restTemplate = new RestTemplate();

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
        // Redis 캐시 삭제 (JO_GPT_PROGRAM 서버에 요청)
        try {
            Long memberKey = getMemberKey();
            restTemplate.delete(joGptProgramUrl + "/contents/internal/google-token-cache/" + memberKey);
        } catch (Exception e) {
            // 캐시 삭제 실패해도 연동 해제는 진행
        }
        connectedAccountsService.disconnect(accountKey);
        return ResponseEntity.ok().build();
    }
}
