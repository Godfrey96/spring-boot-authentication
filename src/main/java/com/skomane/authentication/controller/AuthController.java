package com.skomane.authentication.controller;

import com.skomane.authentication.dto.JwtResponseDto;
import com.skomane.authentication.dto.LoginRequestDto;
import com.skomane.authentication.dto.SignupRequestDto;
import com.skomane.authentication.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signin")
    public JwtResponseDto signin(@Valid @RequestBody LoginRequestDto loginRequest){
        return authService.loginUser(loginRequest);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupRequestDto signupRequest){
        authService.registerUser(signupRequest);
        return new ResponseEntity<>("User Registration Successful", HttpStatus.CREATED);
    }


}
