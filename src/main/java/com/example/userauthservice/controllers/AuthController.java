package com.example.userauthservice.controllers;

import com.example.userauthservice.dtos.LoginRequestDto;
import com.example.userauthservice.dtos.SignUpRequestDto;
import com.example.userauthservice.dtos.UserDto;
import com.example.userauthservice.dtos.ValidateTokenRequestDto;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    public UserDto signup(@RequestBody SignUpRequestDto signUpDto){
        return null;
    }

    public UserDto login(@RequestBody LoginRequestDto loginRequestDto){
        return null;
    }

    public Boolean validateToken(@RequestBody ValidateTokenRequestDto validateTokenRequestDto) {
        return null;
    }

    // pending logout and forgotPassword implementation
}
