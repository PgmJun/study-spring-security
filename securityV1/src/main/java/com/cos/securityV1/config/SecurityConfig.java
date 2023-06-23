package com.cos.securityV1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // 해당 어노테이션 활성 시, 스프링 시큐리티 필터가 스프링 필터채인에 등록 됨
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)
//securedEnabled = true => Controller의 특정 요청에 대해서 권한 설정을 부여하는 @Secured 어노테이션 사용 활성화
//prePostEnabled = true => Controller의 특정 요청이 수행되기 전에 실행되는 @PreAuthorize, 수행된 이후 실행되는 @PostAuthorize어노테이션 활성화
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.csrf(AbstractHttpConfigurer::disable);
        http.authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers("/user/**").authenticated()
                                .requestMatchers("/manager/**").hasAnyRole("ADMIN", "MANAGER")
                                .requestMatchers("/admin/**").hasAnyRole("ADMIN")
                                .anyRequest().permitAll()
                )
                .formLogin(formLogin ->
                        formLogin
                                .loginPage("/loginForm") //권한이 없으면 로그인페이지로 이동시키기
                                .loginProcessingUrl("/login") // /login 주소가 호출되면 시큐리티가 낚아채서 대신 로그인을 진행해준다.
                                .defaultSuccessUrl("/") // login 성공 시, 이동 페이지
                )
                .oauth2Login(oauth2Login ->
                        oauth2Login.loginPage("/loginForm")); // 구글 로그인 완료 후 후처리가 필요

        return http.build();

    }


}
