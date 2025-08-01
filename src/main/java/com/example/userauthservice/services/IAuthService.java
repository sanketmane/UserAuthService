package com.example.userauthservice.services;

import com.example.userauthservice.dtos.ValidateTokenRequestDto;
import com.example.userauthservice.models.User;
import com.example.userauthservice.repos.UserRepo;
import org.antlr.v4.runtime.misc.Pair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;


public interface IAuthService {

    User signup(String name, String email, String password, String phoneNumber);

    Pair<User, String> login(String username, String password);
    Boolean validateToken(String token, Long userId);
}
