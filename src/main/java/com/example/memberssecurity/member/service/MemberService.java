package com.example.memberssecurity.member.service;

import com.example.entitycom.entity.member.AuthProviders;
import com.example.entitycom.entity.member.Members;
import com.example.entitycom.entity.member.UserCredentials;
import com.example.entitycom.enums.Role;

import com.example.memberssecurity.member.dto.request.SignUpDto;
import com.example.memberssecurity.member.dto.response.MemberDto;
import com.example.memberssecurity.member.repository.jpa.AuthProviderRepository;
import com.example.memberssecurity.member.repository.jpa.MemberRepository;
import com.example.memberssecurity.member.repository.jpa.UserCredentialsRepository;
import com.example.memberssecurity.security.config.dto.social.dto.SocialUserInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@Slf4j
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    // PasswordConfig 클래스를 임포트하지 않는 이유는 이 클래스는 빈을 등록하는 클래스이고 메서드가 빈으로 등록되었으면 실행될 때 자동으로 해당 메서드가 실행된다.
    // PasswordEncoder는 규칙(인터페이스)이고, BCryptPasswordEncoder는 그 규칙의 구현체이다.
    private final UserCredentialsRepository userCredentialsRepository;
    private final AuthProviderRepository authProvidersRepository;
    /*
     * 회원가입 기능
     * - 중복된 username 체크
     * - 비밀번호 암호화 후 저장
     * */

    @Transactional
    public void signUp(SignUpDto signUpDto) {
        // 1. 중복 가입 체크 (아이디 중복 시 예외 발생으로 트랜잭션 중단)
        validateDuplicateUsername(signUpDto.getMemberId());
            //Members 엔티티 생성 밎 정보 설정
            Members members = new Members();
            members.changeMemberId(signUpDto.getMemberId());
            members.changeRole(signUpDto.getRole());
            members.changeAge(signUpDto.getAge());
            members.changeGender(signUpDto.getGender());
            members.changeName(signUpDto.getName());
            members.changePhone(signUpDto.getPhone());

            // 3. UserCredentials 엔티티 생성 및 비밀번호 암호화
            UserCredentials userCredentials = new UserCredentials();
            userCredentials.changeUserPw(passwordEncoder.encode(signUpDto.getUserPw()));
            // Members -> UserCredentials 연결
            // Members.changeUserCredentials 안에 들어가면 userCredentials.changeMemberKey(this) 도 호출됨
            members.changeUserCredentials(userCredentials);
            // 부모인 Members를 저장하면 Cascade.ALL을 통해 UserCredentials도 저장되며,
            // @MapsId에 의해 members의 PK가 UserCredentials의 PK이자 FK로 자동 주입됩니다.
            memberRepository.save(members);

    }

    /*
     * 중복된 username 체크
     * */

    private void validateDuplicateUsername(String memberId) {
        if (memberId == null || memberId.isEmpty()) {
            throw new RuntimeException("아이디를 입력해주세요.");
        }

        // existsByMemberId를 사용하여 효율적으로 존재 여부 확인
        if (memberRepository.existsByMemberId(memberId)) {
            log.warn("중복된 아이디 가입 시도: {}", memberId);
            throw new RuntimeException("이미 존재하는 아이디입니다.");
        }
    }



    public Members upsertOAuthUser(SocialUserInfo userInfo) {


        Members member = Members.builder()
                .memberId(userInfo.getProvider() + "_" + userInfo.getProviderId())
                .name(userInfo.getName())
                .role(Role.ROLE_USER)
                .build();
        if(!memberRepository.existsByMemberId(member.getMemberId())) {
            Members members = memberRepository.save(member);

            AuthProviders auth_providers = AuthProviders.builder()
                    .provider(userInfo.getProvider())
                    .providerId(userInfo.getProviderId())
                    .member(members)
                    .build();

            authProvidersRepository.save(auth_providers);
            log.debug("OAuth2LoginSuccessHandler: userInfo={}", userInfo);

            return members;
        }else{
            log.debug("OAuth2LoginSuccessHandler: memberId={}", member.getMemberId());
            Long memberKey = memberRepository.findByMemberId(member.getMemberId()).get().getMemberKey();
            log.debug("OAuth2LoginSuccessHandler: memberKey={}", memberKey);
            return memberRepository.findByMemberKey(memberKey).orElseThrow(()-> new RuntimeException("Member not found with key: " + memberKey));
        }
    }

    // MemberService.java
    //사용자 정보를 조회하는 메서드
    public Optional<MemberDto> memberUserInfo(long memberKey) {
        return memberRepository.findByMemberKey(memberKey)
                .map(member -> MemberDto.builder()
                        .memberId(member.getMemberId())
                        .name(member.getName())
                        .phone(member.getPhone())
                        .role(member.getRole())
                        .gender(member.getGender())
                        .age(member.getAge() == null ? 0 : member.getAge())
                        .build());
    }

}
