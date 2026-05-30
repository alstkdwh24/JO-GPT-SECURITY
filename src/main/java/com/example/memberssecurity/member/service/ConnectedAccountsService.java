package com.example.memberssecurity.member.service;

import com.example.entitycom.entity.connect.ConnectedAccounts;
import com.example.entitycom.entity.member.Members;
import com.example.memberssecurity.member.repository.jpa.ConnectedAccountsRepository;
import com.example.memberssecurity.member.repository.jpa.MemberRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ConnectedAccountsService {

    private final ConnectedAccountsRepository connectedAccountsRepository;
    private final MemberRepository memberRepository;

    @Transactional
    public void saveOrUpdate(Long memberKey, String provider, String email,
                             String accessToken, String refreshToken) {
        Members member = memberRepository.findByMemberKey(memberKey).orElseThrow(() -> new RuntimeException("Member not found with key: " + memberKey));

        connectedAccountsRepository.findByMember_MemberKeyAndProvider(memberKey, provider)
                // optional의 상황을 깔끔히 두 경우로 나누어서 해결해주는 함수
                .ifPresentOrElse(
                        account -> account.updateTokens(accessToken, refreshToken, LocalDateTime.now().plusHours(1)
                        ), () -> connectedAccountsRepository.save(ConnectedAccounts.builder()
                                .member(member)
                                .provider(provider)
                                .providerEmail(email)
                                .accessToken(accessToken)
                                .refreshToken(refreshToken)
                                .tokenExpiry(LocalDateTime.now().plusHours(1))
                                .build()));
    }

    public List<Map<String, String>> getList(Long memberKey) {
        return connectedAccountsRepository.findAllByMember_MemberKey(memberKey)
                .stream()
                .map(a -> Map.of(
                        "accountKey", String.valueOf(a.getAccountKey()),
                        "provider", a.getProvider(),
                        "providerEmail", a.getProviderEmail() != null ? a.getProviderEmail() : ""
                ))
                .collect(Collectors.toList());
    }
    public void disconnect(Long accountKey) {
        connectedAccountsRepository.deleteById(accountKey);
    }
}
