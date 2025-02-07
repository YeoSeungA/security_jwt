package com.springboot.config;

import com.springboot.auth.CustomAuthorityUtils;
import com.springboot.auth.filter.JwtAuthenticationFilter;
import com.springboot.auth.filter.JwtVerificationFilter;
import com.springboot.auth.handler.MemberAccessDeniedHandler;
import com.springboot.auth.handler.MemberAuthenticationEntryPoint;
import com.springboot.auth.handler.MemberAuthenticationFailureHandler;
import com.springboot.auth.handler.MemberAuthenticationSuccessHandler;
import com.springboot.auth.jwt.JwtTokenizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
public class SecurityConfiguration {
    private final JwtTokenizer jwtTokenizer;
    private final CustomAuthorityUtils authorityUtils;

    public SecurityConfiguration(JwtTokenizer jwtTokenizer, CustomAuthorityUtils authorityUtils) {
        this.jwtTokenizer = jwtTokenizer;
        this.authorityUtils = authorityUtils;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .headers().frameOptions().sameOrigin()
                .and()
                .csrf().disable()
//                corsConfigurationSource라는 이름으로 등록된 Bean을 이용한다.
                .cors(Customizer.withDefaults())
//                세션을 생성하지 않고, SecurityContext 정보를 얻기 위해 세션을 사용하지 않는다.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
//                JSON 포맷으로 Username과 Password를 전달하기에 폼 로그인 방식 비활성화 하자.
                .formLogin().disable()
//                request를 전송할 때마다 Username/Password 정보를 HTTP Header에 실어 인증하는 방식이다. 비활성화하자.
                .httpBasic().disable()
                .exceptionHandling()
                .authenticationEntryPoint(new MemberAuthenticationEntryPoint())
                .accessDeniedHandler(new MemberAccessDeniedHandler())
                .and()
//                apply()메서드를 이용해 커스터마이징된 Configuration을 추가할 수 있다.
//                CustomConfigurer는 Configuration을 개발자 입맛에 맞게 정의할 수 있는 기능이다.
                .apply(new CustomFilterConfigurer())
                .and()
                .authorizeHttpRequests(authorize -> authorize
//                        회원 등록의 경우 접근 권한여부와 상관없이 누구나 접근이 가능.
                        .antMatchers(HttpMethod.POST, "/*/members").permitAll()
                        .antMatchers(HttpMethod.PATCH,"/*/members/**").hasRole("USER")
                        .antMatchers(HttpMethod.GET,"/*/members").hasRole("ADMIN")
                        .antMatchers(HttpMethod.GET,"/*/members/**").hasAnyRole("USER","ADMIN")
                        .antMatchers(HttpMethod.DELETE,"/*/members/**").hasRole("USER")
//                        커피의 경우
                        .antMatchers(HttpMethod.POST, "/*/coffees").hasRole("ADMIN")
                        .antMatchers(HttpMethod.PATCH,"/*/coffees/**").hasRole("ADMIN")
                        .antMatchers(HttpMethod.GET,"/*/coffees").permitAll()
                        .antMatchers(HttpMethod.GET,"/*/coffees/**").permitAll()
                        .antMatchers(HttpMethod.DELETE,"/*/coffees/**").hasRole("ADMIN")
//                        주문의 경우
                        .antMatchers(HttpMethod.POST, "/*/orders").hasRole("USER")
                        .antMatchers(HttpMethod.PATCH,"/*/orders/**").hasAnyRole("USER","ADMIN")
                        .antMatchers(HttpMethod.GET,"/*/orders").hasRole("ADMIN")
                        .antMatchers(HttpMethod.GET,"/*/orders/**").hasAnyRole("USER","ADMIN")
                        .antMatchers(HttpMethod.DELETE,"/*/orders/**").hasAnyRole("USER","ADMIN")
                        .anyRequest().permitAll());
        return http.build();
    }
//    PasswordEncoder Bean 객체를 생성하자.
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
//    CorsConfigurationSource Bean 생성을 통해 구체적인 CORS 정책을 설정한다.
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
//        모든 출처(Origin)에 대해 스크립트 기반 HTTP 통신이 허용되도록 설정
        corsConfiguration.setAllowedOrigins(Arrays.asList("*"));
//        파라미터로 지정한 HTTP Method 에 대한 HTTP 통신을 허용
        corsConfiguration.setAllowedMethods(Arrays.asList("GET","POST","PATCH","DELETE"));
//         CorsConfigurationSource 인터페이스의 구현클래스 UrlBasedCorsConfigurationSource 클래스 객체를 생성하자.
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        모든 URL에 앞서 구성한 CORS 정책을 적용하자.
        source.registerCorsConfiguration("/**", corsConfiguration);

        return source;
    }
// 우리가 구현한 JwtAuthenticationFilter를 등록하는 역할이다.
    public class CustomFilterConfigurer extends AbstractHttpConfigurer<CustomFilterConfigurer, HttpSecurity> {
        @Override
        public void configure(HttpSecurity builder) throws Exception {
//            getSharedObject()를 통해 Spring Security의 설정을 구성하는 SecurityConfigurer 간의 공유되는 객체를 얻을 수 있다.
            AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
//          JwtAuthenticationFilter 생성하면서 필요한 jwtTokenizer를 DI 해준다.
            JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager, jwtTokenizer);
//           .setFilterProcessesUrl()를 통해 디폴트 request URL인 "/login"을 "/v11/auth/login"으로 변경한다.
            jwtAuthenticationFilter.setFilterProcessesUrl("/v11/auth/login");
//            성공, 실패시 handeler class 추가
            jwtAuthenticationFilter.setAuthenticationSuccessHandler(new MemberAuthenticationSuccessHandler());
            jwtAuthenticationFilter.setAuthenticationFailureHandler(new MemberAuthenticationFailureHandler());

            JwtVerificationFilter jwtVerificationFilter = new JwtVerificationFilter(jwtTokenizer, authorityUtils);
//          addFilter를 통해 JwtAuthenticationFilter를 Spring Security Chain에 추가한다.
            builder.addFilter(jwtAuthenticationFilter)
//                    jwtVerificationFiter는 JwtAuthenticatinFilter에서 로그인 인증에 성공한 후 발급받은 JWT가 클라이언트의
//                    request header(Authorization 헤더)에 포함돼 있을 경우에만 동작한다.
                    .addFilterAfter(jwtVerificationFilter, JwtAuthenticationFilter.class);
        }
    }
}
