package com.cos.securityV1.oauth;

import com.cos.securityV1.auth.PrincipalDetails;
import com.cos.securityV1.model.User;
import com.cos.securityV1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final BCryptPasswordEncoder encoder;
    private final UserRepository userRepository;

    // 구글로 부터 받은 userRequest 데이터에 대한 후처리되는 함수
    // 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어진다.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("userRequest.getAccessToken() = " + userRequest.getAccessToken()); //registrationId로 어떤 OAuth로 로그인 했는지
        // 구글 로그인 버튼 클릭 -> 구글로그인창 -> 로그인 완료 -> code를 리턴(OAuth-Client라이브러리) -> AccessToken 요청
        // userRequest 정보 -> loadUser함수 호출 -> 구글 회원프로필 받아줌
        OAuth2User oauth2User = super.loadUser(userRequest);
        System.out.println("super.loadUser(userRequest).getAttributes() = " + oauth2User.getAttributes());

        String provider = userRequest.getClientRegistration().getClientId();//google
        String providerId = oauth2User.getAttribute("sub"); // google의 회원 PK
        String username = provider + "_" + providerId; // google_12412795810241
        String password = encoder.encode("겟인데어");
        String email = oauth2User.getAttribute("email");
        String role = "ROLE_USER";

        Optional<User> userEntity = userRepository.findByUsername(username);

        if(userEntity.isEmpty()) {
            userEntity = Optional.of(User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build());

            userRepository.save(userEntity.get());
        }

        return new PrincipalDetails(userEntity.get(), oauth2User.getAttributes());
    }
}
