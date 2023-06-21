package com.cos.securityV1.repository;

import com.cos.securityV1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

// CRUD 함수를 JpaRepository가 들고 있음.
// @Repository 라는 Annotation이 없어도 IoC가 된다. 이유는 JpaRepository를 상속했기 떄문
public interface UserRepository extends JpaRepository<User, Integer> {

    Optional<User> findByUsername(String username);
}
