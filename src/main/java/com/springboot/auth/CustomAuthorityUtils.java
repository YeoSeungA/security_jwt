package com.springboot.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class CustomAuthorityUtils {
    @Value("${mail.address.admin}")
    private String adminMailAddress;
//    Security에서 다루는 권한의 객체 GranedAuthority List로 만들자.
    private final List<GrantedAuthority> ADMIN_ROLES =
            AuthorityUtils.createAuthorityList("ROLE_ADMIN","ROLE_USER");

    private final List<GrantedAuthority> USER_ROLES =
            AuthorityUtils.createAuthorityList("ROLE_USER");
//    DB에 저장되어 있는 권한은 String 타입이므로 정의하자.
    private final List<String> ADMIN_ROLES_STRING = List.of("ADMIN", "USER");
    private final List<String> USER_ROLES_STRING = List.of("USER");
//    emil을 파라미터로 받아 권한을 생성하는 메서드
    public List<String> creteRole(String email) {
        if(email.equals(adminMailAddress)) {
            return ADMIN_ROLES_STRING;
        } else {
            return USER_ROLES_STRING;
        }
    }

    public List<GrantedAuthority> createAuthorities(List<String> roles) {
//        List를 순회하며 DB의 저장되있던 권한을 (String) Security에 저장하기 위한 GrantedAuthority로 mapping 하자.
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());
    }
}
