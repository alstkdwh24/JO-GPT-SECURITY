package com.example.memberssecurity.member.service;

import com.example.entitycom.entity.member.Members;
import com.example.memberssecurity.member.repository.jpa.MemberRepository;
import com.example.memberssecurity.member.repository.jpa.UserCredentialsRepository;
import com.example.memberssecurity.security.config.dto.CustomUserDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    private final UserCredentialsRepository userCredentialsRepository;

    @Override
    public UserDetails loadUserByUsername(String memberId) throws UsernameNotFoundException {

        Optional<Members> membersOptional = memberRepository.findByMemberId(memberId);


        Members members = membersOptional.orElseThrow(() -> new UsernameNotFoundException("해당 사용자를 찾을 수 없습니다."));
        return new CustomUserDetails(members);
    }
}
