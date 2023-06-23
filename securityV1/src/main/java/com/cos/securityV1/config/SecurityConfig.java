package com.cos.securityV1.config;

import com.cos.securityV1.auth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
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

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

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
                                .loginPage("/loginForm") // 권한이 없으면 로그인페이지로 이동시키기
                                .loginProcessingUrl("/login") // /login 주소가 호출되면 시큐리티가 낚아채서 대신 로그인을 진행해준다.
                                .defaultSuccessUrl("/") // login 성공 시, 이동 페이지
                )
                .oauth2Login(oauth2Login ->
                        oauth2Login.loginPage("/loginForm") // 구글 로그인
                                //완료된 후 후처리가 필요함.
                                // 1. 코드받기(인증) 2. 엑세스토큰 받기(권한) 3. 권한을 통해 사용자 프로필정보 가져오기
                                // 4-1. 그 정보를 토대로 회원가입 자동으로 진행시키기도 함
                                // 4-2. 집주소,전화번호 등의 추가적인 정보가 필요하다면? -> 추가적인 회원가입 창이 나와서 입력받도록 해야함
                                // Oauth2 Client 라이브러리는 로그인 시 코드가 아닌 엑세스토큰+프로필정보를 받아와 줌(개꿀)
                                .userInfoEndpoint(userInfoEndpoint ->
                                        userInfoEndpoint
                                                .userService(principalOauth2UserService)
                                )
                );

        return http.build();

    }


}
