package com.auth.springsecurity.services;

import com.auth.springsecurity.dto.JWTAuthenticationResponse;
import com.auth.springsecurity.dto.RefreshTokenResponse;
import com.auth.springsecurity.dto.SignInRequest;
import com.auth.springsecurity.dto.SignUpRequest;
import com.auth.springsecurity.entities.User;

public interface AuthenticationService {
    User SignUp(SignUpRequest signUpRequest);
    JWTAuthenticationResponse SignIn(SignInRequest signInRequest);
    JWTAuthenticationResponse RefreshToken(RefreshTokenResponse refreshTokenResponse);
}
