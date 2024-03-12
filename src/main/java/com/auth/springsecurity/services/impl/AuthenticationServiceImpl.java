package com.auth.springsecurity.services.impl;

import com.auth.springsecurity.dto.JWTAuthenticationResponse;
import com.auth.springsecurity.dto.RefreshTokenResponse;
import com.auth.springsecurity.dto.SignInRequest;
import com.auth.springsecurity.dto.SignUpRequest;
import com.auth.springsecurity.entities.Role;
import com.auth.springsecurity.entities.User;
import com.auth.springsecurity.repository.UserRepository;
import com.auth.springsecurity.services.AuthenticationService;
import com.auth.springsecurity.services.JWTService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JWTService jwtService;
    public User SignUp(SignUpRequest signUpRequest) {
         User user=new User();
         user.setEmail(signUpRequest.getEmail());
         user.setFirstname(signUpRequest.getFirstName());
         user.setLastname(signUpRequest.getLastName());
         user.setRole(Role.USER);
         user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));
          userRepository.save(user);
        user.setPassword(null);
        return user;
    }

    public JWTAuthenticationResponse SignIn(SignInRequest signInRequest) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                signInRequest.getEmail(),
                signInRequest.getPassword()
        ));
        var user= userRepository.findByEmail(signInRequest.getEmail())
                .orElseThrow(()->new IllegalArgumentException("User not found"));
        var jwt=jwtService.generateToken(user);
        var refreshToken=jwtService.generateRefreshToken(new HashMap<>(),user);
        JWTAuthenticationResponse jwtAuthenticationResponse=new JWTAuthenticationResponse();
        jwtAuthenticationResponse.setToken(jwt);
        jwtAuthenticationResponse.setRefreshToken(refreshToken);
        return jwtAuthenticationResponse;
    }

    public JWTAuthenticationResponse RefreshToken(RefreshTokenResponse refreshTokenResponse) {
        String userEmail=jwtService.extractUsername(refreshTokenResponse.getToken());
        var user= userRepository.findByEmail(userEmail)
                .orElseThrow(()->new IllegalArgumentException("User not found"));
        if(!jwtService.isTokenValid(refreshTokenResponse.getToken(),user)){
            throw new IllegalArgumentException("Invalid token");
        }
        var jwt=jwtService.generateToken(user);
        var refreshToken=jwtService.generateRefreshToken(new HashMap<>(),user);
        JWTAuthenticationResponse jwtAuthenticationResponse=new JWTAuthenticationResponse();
        jwtAuthenticationResponse.setToken(jwt);
        jwtAuthenticationResponse.setRefreshToken(refreshToken);
        return jwtAuthenticationResponse;
    }
}
