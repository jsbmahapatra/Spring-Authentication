package com.springsecurity.Authenticator.controller;

import com.springsecurity.Authenticator.user.User;
import org.springframework.cglib.proxy.Dispatcher;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.DispatcherServlet;

@RestController
@RequestMapping("/hello")
public class HelloRestController {


    @GetMapping("/user")
    public String helloUser() {
        return "Hello User";
    }

    //@PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String helloAdmin() {
        return "Hello Admin";
    }

    @PostMapping("/user")
    public User add(User user) {
        return user;
    }

}