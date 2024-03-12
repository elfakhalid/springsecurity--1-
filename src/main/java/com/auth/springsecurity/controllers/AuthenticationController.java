package com.auth.springsecurity.controllers;

import com.auth.springsecurity.dto.JWTAuthenticationResponse;
import com.auth.springsecurity.dto.RefreshTokenResponse;
import com.auth.springsecurity.dto.SignInRequest;
import com.auth.springsecurity.dto.SignUpRequest;
import com.auth.springsecurity.entities.User;
import com.auth.springsecurity.services.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    @PostMapping("/signup")
    public ResponseEntity<User> SignUp(@RequestBody SignUpRequest signUpRequest) {
        return ResponseEntity.ok(authenticationService.SignUp(signUpRequest));
    }

    @PostMapping("/signin")
    public ResponseEntity<JWTAuthenticationResponse> SignIn(@RequestBody SignInRequest signInRequest) {
        return ResponseEntity.ok(authenticationService.SignIn(signInRequest));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<JWTAuthenticationResponse> Refresh(@RequestBody RefreshTokenResponse refreshTokenResponse) {
        return ResponseEntity.ok(authenticationService.RefreshToken(refreshTokenResponse));
    }
}
