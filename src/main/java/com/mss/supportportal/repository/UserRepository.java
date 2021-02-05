package com.mss.supportportal.repository;

import com.mss.supportportal.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

    User findByUserName(String userName);
    User findByEmail(String email);
}
