package com.example.memberssecurity.security.config.dto;

import com.example.entitycom.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CustomUserInfoDto {

    private String id;
    private String memberId;
    private String userPw;
    private String name;
    private Role role;
    private String phone;
    private String gender;
    private int age;
}
