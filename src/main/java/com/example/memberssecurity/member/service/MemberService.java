package com.example.memberssecurity.member.service;

import com.example.entitycom.entity.member.AuthProviders;
import com.example.entitycom.entity.member.Members;
import com.example.entitycom.entity.member.UserCredentials;
import com.example.entitycom.enums.Role;
import com.example.memberssecurity.member.dto.request.LoginDto;
import com.example.memberssecurity.member.dto.request.SignUpDto;
import com.example.memberssecurity.member.dto.response.MemberDto;
import com.example.memberssecurity.member.repository.jpa.AuthProviderRepository;
import com.example.memberssecurity.member.repository.jpa.MemberRepository;
import com.example.memberssecurity.member.repository.jpa.UserCredentialsRepository;
import com.example.memberssecurity.security.config.dto.social.dto.SocialUserInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class MemberService implements UserDetailsService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    // PasswordConfig 클래스를 임포트하지 않는 이유는 이 클래스는 빈을 등록하는 클래스이고 메서드가 빈으로 등록되었으면 실행될 때
    // 자동으로 해당 메서드가 실행된다.
    // PasswordEncoder는 규칙(인터페이스)이고, BCryptPasswordEncoder는 그 규칙의 구현체이다.
    private final UserCredentialsRepository userCredentialsRepository;
    private final AuthProviderRepository authProvidersRepository;
    /*
     * 회원가입 기능
     * - 중복된 username 체크
     * - 비밀번호 암호화 후 저장
     */

    @Transactional
    public void signUp(SignUpDto signUpDto) {
        // 1. 중복 가입 체크 (아이디 중복 시 예외 발생으로 트랜잭션 중단)
        validateDuplicateUsername(signUpDto.getMemberId());
        // Members 엔티티 생성 밎 정보 설정
        Members members = new Members();
        members.changeMemberId(signUpDto.getMemberId());
        members.changeRole(signUpDto.getRole());

        members.changeNickname(signUpDto.getNickname());

        // 3. UserCredentials 엔티티 생성 및 비밀번호 암호화
        UserCredentials userCredentials = new UserCredentials();
        userCredentials.changeUserPw(passwordEncoder.encode(signUpDto.getUserPw()));
        // Members -> UserCredentials 연결
        // Members.changeUserCredentials 안에 들어가면 userCredentials.changeMemberKey(this) 도
        // 호출됨
        members.changeUserCredentials(userCredentials);
        // 부모인 Members를 저장하면 Cascade.ALL을 통해 UserCredentials도 저장되며,
        // @MapsId에 의해 members의 PK가 UserCredentials의 PK이자 FK로 자동 주입됩니다.
        memberRepository.save(members);

    }

    /*
     * 중복된 username 체크
     */

    private void validateDuplicateUsername(String memberId) {
        if (memberId == null || memberId.isEmpty()) {
            throw new RuntimeException("아이디를 입력해주세요.");
        }

        // existsByMemberId를 사용하여 효율적으로 존재 여부 확인
        if (memberRepository.existsByMemberId(memberId)) {
            throw new RuntimeException("이미 존재하는 아이디입니다.");
        }
    }

    public Members login(LoginDto dto) {

//  이렇게 해야 해요 - memberId로 조회하고 결과를 members에 담아요
        Members members = memberRepository.findByMemberIdWithCredentials(dto.getMemberId())
                .orElseThrow(() -> new RuntimeException("아이디 비번이 올바르지가 않습니다."));


        //  결과를 확인해야 해요
        if (!passwordEncoder.matches(dto.getUserPw(), members.getUserCredentials().getUserPw())) {
            throw new RuntimeException("아이디 또는 비밀번호가 올바르지 않습니다.");
        }
        return members;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return null;
    }

    public record OAuthResult(Members member, boolean isNew) {
    }

    public OAuthResult upsertOAuthUser(SocialUserInfo userInfo) {
        String memberId = userInfo.getProvider() + "_" + userInfo.getProviderId();

        // 신규 가입 시 닉네임 설정 화면에서 입력하도록 임시 닉네임 사용
        String nickname = memberId;

        if (!memberRepository.existsByMemberId(memberId)) {
            Members members = Objects.requireNonNull(memberRepository.save(Members.builder()
                    .memberId(memberId)
                    .nickname(nickname)
                    .role(Role.ROLE_USER)
                    .build()));

            authProvidersRepository.save(AuthProviders.builder()
                    .provider(userInfo.getProvider())
                    .providerId(userInfo.getProviderId())
                    .member(members)
                    .build());

            return new OAuthResult(members, true);
        } else {
            Long memberKey = memberRepository.findByMemberId(memberId).get().getMemberKey();
            return new OAuthResult(
                    memberRepository.findByMemberKey(memberKey)
                            .orElseThrow(() -> new RuntimeException("Member not found with key: " + memberKey)),
                    false);
        }
    }
    // 닉네임 설정
    @Transactional
    public void updateNickname(Long memberKey, String nickname) {
        Members member = memberRepository.findByMemberKey(memberKey)
                .orElseThrow(() -> new RuntimeException("Member not found with key: " + memberKey));
        member.changeNickname(nickname);
        memberRepository.save(member);
    }

    // MemberService.java
    // 사용자 정보를 조회하는 메서드
    public Optional<MemberDto> memberUserInfo(long memberKey) {
        return memberRepository.findByMemberKey(memberKey)
                .map(member -> MemberDto.builder()
                        .memberId(member.getMemberId())
                        .role(member.getRole())
                        .nickname(member.getNickname())
                        .build());
    }

}
