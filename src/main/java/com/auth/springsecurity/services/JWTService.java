package com.auth.springsecurity.services;

import org.springframework.security.core.userdetails.UserDetails;

import java.util.Map;

public interface JWTService {
     String extractUsername(String token);
     String generateToken(UserDetails userDetails);
     boolean isTokenValid(String token,UserDetails userDetails);
     String generateRefreshToken(Map<String,Object> extraCliams, UserDetails userDetails);
}
