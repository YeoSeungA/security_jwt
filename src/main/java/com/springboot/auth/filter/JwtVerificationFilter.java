package com.springboot.auth.filter;

import com.springboot.auth.CustomAuthorityUtils;
import com.springboot.auth.jwt.JwtTokenizer;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

//클라이언트 측에서 JWT를 이용해 자격 증명이 필요한 리소스에 대한 request 전송 시, request header를 통해 전달받은 JWT를 서버 측에서 검증하는 기능구현./
// OncePerRequestFilter를 상속받아 request 당 한번만 실행되는 Security Filter를 구현할 수 있다.
public class JwtVerificationFilter extends OncePerRequestFilter {
//     JWT를 검증하고 Cloiams(토큰에 포함된 정보)를 얻는데 사용
    private final JwtTokenizer jwtTokenizer;
//    JWT를 검증에 성공시, Authenticatiuon 객체에 채울 사용자의 권한을 생성하는데 사용된다.
    private final CustomAuthorityUtils authorityUtils;

    public JwtVerificationFilter(JwtTokenizer jwtTokenizer, CustomAuthorityUtils authorityUtils) {
        this.jwtTokenizer = jwtTokenizer;
        this.authorityUtils = authorityUtils;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain){
//        verifyJws()메서든는 JWT를 검증하는데 사용되는 private 메서드이다.
        Map<String, Object> claims = verifyJws(request);
        setAuthenticationToContext(claims);

        filterChain.doFilter(request,response);
    }
}
