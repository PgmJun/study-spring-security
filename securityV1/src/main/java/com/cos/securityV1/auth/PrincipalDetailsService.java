package com.cos.securityV1.auth;

import com.cos.securityV1.model.User;
import com.cos.securityV1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

// 시큐리티 설정에서 loginProcessingUrl("/login");
// /login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC 되어 있는 loadUserByUsername 함수가 실행
@Service
public class PrincipalDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    public PrincipalDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // 시큐리티 Session(내부 Authentication(내부 UserDetails)) 형태 중 UserDetails return
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userEntity = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("존재하지 않는 회원 입니다"));

        return new PrincipalDetails(userEntity);

    }
}
