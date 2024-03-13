package com.auth.springsecurity.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class AdminController {
@GetMapping("/admin")
@PreAuthorize("hasAnyAuthority('USER')")
    public ResponseEntity<String> admin(){
        return ResponseEntity.ok("hello Admin");
    }

}
