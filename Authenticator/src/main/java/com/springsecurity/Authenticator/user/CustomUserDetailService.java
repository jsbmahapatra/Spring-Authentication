package com.springsecurity.Authenticator.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailService implements UserDetailsService {
    //  @Autowired
    //private UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //  User user = userRepository.findByUserName(username);
        User user = new User();
        user.setUsername("ram");
        user.setPassword("password");
        user.setRole("NORMAL");
        user.setId("1");
        if (!user.getUsername().equals(username)) {
            throw new UsernameNotFoundException("User Not Found");
        }
        return new CustomUserDetails(user);
    }
}
