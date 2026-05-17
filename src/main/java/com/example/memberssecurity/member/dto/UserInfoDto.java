package com.example.memberssecurity.member.dto;

import com.example.entitycom.enums.Role;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserInfoDto {
    private String id;
    private String memberId;
    private String nickname;
    private Role role;

}
