package com.springsecurity.Authenticator.controller;

import com.springsecurity.Authenticator.helper.JwtUtil;
import com.springsecurity.Authenticator.model.JwtRequest;
import com.springsecurity.Authenticator.model.JwtResponse;
import com.springsecurity.Authenticator.user.CustomUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwtController {
    @Autowired
    private CustomUserDetailService customUserDetailService;
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private AuthenticationManager authenticationManager;

    @RequestMapping(value = "/token", method = RequestMethod.POST)
    public ResponseEntity<?> generateToken(@RequestBody JwtRequest jwtRequest) {
        System.out.println(jwtRequest);
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            jwtRequest.getUsername(),
                            jwtRequest.getPassword()));
        } catch (UsernameNotFoundException ex) {
            throw new BadCredentialsException("Some Error");
        } catch (BadCredentialsException ex) {
            throw new BadCredentialsException("Bad Credential");
        }
        UserDetails userDetails = customUserDetailService.loadUserByUsername(jwtRequest.getUsername());
        String token = jwtUtil.generateToken(userDetails);
        System.out.println("JWT Token = " + token);
        return ResponseEntity.ok(new JwtResponse(token));
    }
}
