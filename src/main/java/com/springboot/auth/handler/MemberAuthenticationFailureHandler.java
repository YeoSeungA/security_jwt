package com.springboot.auth.handler;

import com.google.gson.Gson;
import com.springboot.response.ErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
// 로그인 인증 실패시 추가 작업을 할 수 있는 코드
@Slf4j
public class MemberAuthenticationFailureHandler implements AuthenticationFailureHandler {
//AuthenticationFailureHandler에는 onAuthenticationFailure() 추상 메서드가 정의 돼있다.
    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException{
//        인증 실패시 에러 로그를 기록하거나 error response를 전송할 수 있다.
        log.error("# Authentication failed: {}", exception.getMessage());

        sendErrorResponse(response);
    }

    private void sendErrorResponse(HttpServletResponse response) throws IOException {
//        Error 정보가 담긴 객체를 JSON 문자열로 변환하는데 사용되는 Gson 라이브러리의 인스턴스를 생성한다.
        Gson gson = new Gson();
//       ErrorResponse 객체를 생성, UNAUTHORIZED(401) 상태코드는 인증에 실패한 경우 전달할 수 있는 HTTP status이다.
        ErrorResponse errorResponse = ErrorResponse.of(HttpStatus.UNAUTHORIZED);
//        contentType을 알려준다. 이를 HTTP Header에 추가한다.
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//        response의 status가 401 임을 클라이언트에게 알려줄수 있도록 아래를 Header에 추가한다.
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        // Gson을 이용해 ErrorResponse 객체를 JSON 포맷 문자열로 변환, 출력 스트림을 생성한다.
        response.getWriter().write(gson.toJson(errorResponse, ErrorResponse.class));
    }
}
