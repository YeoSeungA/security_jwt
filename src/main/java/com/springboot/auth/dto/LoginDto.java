package com.springboot.auth.dto;

import lombok.Getter;
// 로그인 인증 정보 역직렬화(Deserialization)를 위한 LoginDto클래스 생성
@Getter
public class LoginDto {
    private String username;
    private String password;
}
