package com.example.userauthservice.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SignUpRequestDto {
    // We need to create this separate dto from UserDto for signup process
    private String name;
    private String email;
    private String password;
    private String phoneNumber;
}
