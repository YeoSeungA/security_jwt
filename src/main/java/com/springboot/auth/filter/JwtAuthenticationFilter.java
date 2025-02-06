package com.springboot.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.springboot.auth.dto.LoginDto;
import com.springboot.auth.jwt.JwtTokenizer;
import com.springboot.member.entity.Member;
import lombok.SneakyThrows;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

//UsernamePasswordAuthenticationFilter 는 폼 로그인에서 사용하는 Security Filter로써, 폼 고르인이 아니더라도 Username/Passsword 기반의 인증처리를 위해
// 확장해 구현하였다.
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
//    로그인 인증 정보(username/password) 를 전달받아 UserDetailService와 인터랙션 후 인증 여부를 판단.
    private final AuthenticationManager authenticationManager;
//    클라이언트가 인증에 성공할 경우, Jst를 생성 및 발급하는 역할을 한다.
    private final JwtTokenizer jwtTokenizer;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, JwtTokenizer jwtTokenizer) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenizer = jwtTokenizer;
    }
// 오버라이드를 재정의??? 예외 처리를 bypass 남발은 X.
    @SneakyThrows
    @Override
//    메서드 내부에서 인증을 시도한다.
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
// 클라이언트에게 전송한 username과 password를 dto 클래스로 역직렬화하기 위해 ObjectMapper인스턴스를 생성
        ObjectMapper objectMapper = new ObjectMapper();
//        ServletInputStream을 LoginDto 클래스의 객체로 역직렬화 한다.
        LoginDto loginDto = objectMapper.readValue(request.getInputStream(), LoginDto.class);
//      username과 password 정보를 포함한 토큰을 생성
        UsernamePasswordAuthenticationToken authenticationToken=
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());
//        uernamePasswordAuthenticationToken을 AuthenticationManger에게 전달해 인증처리를 위임한다.
        return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws ServletException, IOException {
//        Member 엔티티 클래스의 객체를 얻는다.
//        AutheneicationManager 내부에서 인증에 성공하면 인증된 Authentication 객체가 생성되면서 principal 필드에 Member 객체가 할당된다..
        Member member = (Member) authResult.getPrincipal();

        String accessToken = delegateAccessToken(member);
        String refreshToken = delegateRefreshToken(member);
//      response 헤더에 Access 토큰을 추가한다.
        response.setHeader("Authorization", "Bearer " + accessToken);
        response.setHeader("Refresh", refreshToken);
// onAuthenticationSuccess()를 호출하면 앞서 구현한 MemberAuthenticationSuccessHandler의 onAuthenticationSuccess() 메서드가 호출된다.
//        MemberAuthenticationFailureHandler는 별도의 코드를 추가하지 않아도 로그인 인증에 실패하면 우리가 구현한 onAuthenticationFailure가 자동 실행된다.
        this.getSuccessHandler().onAuthenticationSuccess(request,response,authResult);
    }
// Access 토큰을 생성한다.
    private String delegateAccessToken(Member member) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", member.getEmail());
        claims.put("roles", member.getRoles());

        String subject = member.getEmail();
        Date expiration = jwtTokenizer.getTokenExpiration(jwtTokenizer.getAccessTokenExpirationMinutes());

        String base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey());

        String accessToken = jwtTokenizer.generateAccessToken(claims, subject, expiration, base64EncodedSecretKey);

        return accessToken;
    }
// Refresh 토큰을 생성합니다.
    private String delegateRefreshToken(Member member) {
        String subject = member.getEmail();
        Date expiration = jwtTokenizer.getTokenExpiration(jwtTokenizer.getRefreshTokenExpirationMinutes());
        String base64EncodedSecretKey = jwtTokenizer.encodeBase64SecretKey(jwtTokenizer.getSecretKey());

        String refreshToken = jwtTokenizer.generateRefreshToken(subject,expiration,base64EncodedSecretKey);
        return refreshToken;
    }
}
