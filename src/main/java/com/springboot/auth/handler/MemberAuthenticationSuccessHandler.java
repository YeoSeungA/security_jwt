package com.springboot.auth.handler;


import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class MemberAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
//    단순히 로그만 출력하고 있지만, Authentication 객체에 사용자 정보를 얻은 후, HttpServletResponse로 출력 스트림을 생성해,
//    response 를 전송할 수 있다.
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) {
//        인증 성공 후, 로그를 기록하거나 사용자 정보를 response로 전송하는 등의 추가작업을 할 수 있다.
        log.info("# Authenticated successfully");
    }
}
