package com.cos.securityV1.auth;

// 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다.
// 로그인을 진행이 완료가 되면 session을 만들어줍니다. (Security ContextHolder에 Session정보 저장)
// 세션정보 오브젝트 => Authentication 객체
// Authentication 안에 User 정보가 있어야 됨.
// User오브젝트 타입 => UserDetails 타입 객체

// 정리
// Security Session => Authentication => UserDetails(PrincipalDetails)

import com.cos.securityV1.model.User;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@Getter
public class PrincipalDetails implements UserDetails, OAuth2User {

    private User user; //콤포지션

    public PrincipalDetails(User user) {
        this.user = user;
    }

    @Override
    public <A> A getAttribute(String name) {
        return OAuth2User.super.getAttribute(name);
    }

    @Override
    public Map<String, Object> getAttributes() {
        return null;
    }

    // 해당 유저의 권한을 리턴하는 곳
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();

        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    // 해당 계정이 만료되었는가
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 해당 계정이 잠겼는가
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 해당 계정의 Password가 특정 기간이 지났는가
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 해당 계정이 활성화 되어있는가
    @Override
    public boolean isEnabled() {

        return true;
    }

    @Override
    public String getName() {
        return null;
    }
}
