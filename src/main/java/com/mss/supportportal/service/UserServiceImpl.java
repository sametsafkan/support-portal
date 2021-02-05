package com.mss.supportportal.service;

import com.mss.supportportal.repository.UserRepository;
import com.mss.supportportal.domain.User;
import com.mss.supportportal.domain.UserPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Slf4j
@Service
@Qualifier("userDetailsService")
@RequiredArgsConstructor
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        User user = userRepository.findByUserName(userName);
        if (user == null) {
            log.error("User not found : " + userName);
            throw new UsernameNotFoundException("User not found : " + userName);
        }
        user.setLastLoginDateDisplay(user.getLastLoginDate());
        user.setLastLoginDate(LocalDateTime.now());
        return new UserPrincipal(user);
    }
}
