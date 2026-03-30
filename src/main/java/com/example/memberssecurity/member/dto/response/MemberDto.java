package com.example.memberssecurity.member.dto.response;

import com.example.entitycom.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class MemberDto {
    private Long id;

    private String memberId;
    private String name;

    private String userPw;

    private String phone;

    private Role role;

    private String gender;

    private int age;

}
