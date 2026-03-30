package com.example.memberssecurity.member.dto.request;

import com.example.entitycom.enums.Role;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SignUpDto {
    @JsonIgnore // 에러방지, 보안 및 정합성

    private Long id;

    private String memberId;
    private String name;

    private String userPw;

    private String phone;

    private Role role;

    private String gender;

    private int age;


}
