package com.example.userauthservice.controllers;

import com.example.userauthservice.dtos.LoginRequestDto;
import com.example.userauthservice.dtos.SignUpRequestDto;
import com.example.userauthservice.dtos.UserDto;
import com.example.userauthservice.dtos.ValidateTokenRequestDto;
import com.example.userauthservice.exceptions.UnauthorizedException;
import com.example.userauthservice.models.User;
import com.example.userauthservice.services.IAuthService;
import org.antlr.v4.runtime.misc.Pair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private IAuthService authService;

    @PostMapping("/signup")
    public UserDto signup(@RequestBody SignUpRequestDto signUpDto){
        String name = signUpDto.getName();
        String email = signUpDto.getEmail();
        String password = signUpDto.getPassword();
        String phoneNumber = signUpDto.getPhoneNumber();
        User user = authService.signup(name, email, password, phoneNumber);
        return from(user);
    }

    @PostMapping("/login")
    // test by making post login and check cookie in response
    // copy the jwt and check in jwt.io
    public ResponseEntity<UserDto> login(@RequestBody LoginRequestDto loginRequestDto){
        String email = loginRequestDto.getEmail();
        String password = loginRequestDto.getPassword();
        Pair<User,String> response = authService.login(email, password);
        // Since Pair object consists of 2 objects,
        // they can be accessed as object.a and object.b
        UserDto userDto = from(response.a); // prepare userDto object from User object
        String token = response.b;

        // To set headers, you need to use MultiValueMap only
        // jwt is set in cookie
        MultiValueMap<String,String> headers = new LinkedMultiValueMap<>();
        headers.add(HttpHeaders.SET_COOKIE, token);
        return new ResponseEntity<UserDto>(userDto, headers, HttpStatus.OK);
    }

    @PostMapping("/validateToken")
    public Boolean validateToken(@RequestBody ValidateTokenRequestDto validateTokenRequestDto) {

        Boolean tokenStatus = authService.validateToken(
                validateTokenRequestDto.getToken(),
                validateTokenRequestDto.getUserId());

        if(!tokenStatus){
            throw new UnauthorizedException("Please login again!");
        }

        return tokenStatus;
    }

    // pending logout and forgotPassword implementation

    private UserDto from(User user) {
        UserDto userDto = new UserDto();
        userDto.setId(user.getId());
        userDto.setEmail(user.getEmail());
        userDto.setUsername(user.getName());
        return userDto;
    }
}
