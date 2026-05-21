package com.example.memberssecurity.member.dto.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter

public class LoginDto {
    private Long id;
    private String memberId;
    private String userPw;

    public LoginDto(String memberId, String userPw) {
        this.memberId = memberId;
        this.userPw = userPw;
    }

    public void ChangeMemberId(String memberId){
        this.memberId = memberId;

    }

    public void ChangeUserPw(String userPw){
        this.userPw = userPw;
    }

}
