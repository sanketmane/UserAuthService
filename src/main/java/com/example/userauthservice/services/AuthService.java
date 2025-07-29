package com.example.userauthservice.services;

import com.example.userauthservice.exceptions.PasswordMismatchException;
import com.example.userauthservice.exceptions.UserAlreadySignedUpException;
import com.example.userauthservice.exceptions.UserNotRegisteredException;
import com.example.userauthservice.models.User;
import com.example.userauthservice.repos.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService implements IAuthService {

    @Autowired
    private UserRepo userRepo;

    @Override
    // Since the actual
    public User signup(String name, String email, String password, String phoneNumber) {
        if (userRepo.findByEmail(email).isPresent()) {
            throw new UserAlreadySignedUpException("Please login directly");
        }

        User user = new User();
        user.setEmail(email);
        user.setPassword(password);
        user.setName(name);
        user.setPhoneNumber(phoneNumber);
        return userRepo.save(user);
    }

    @Override
    public User login(String email, String password){
        Optional<User> userOptional = userRepo.findByEmail(email);
        if(userOptional.isEmpty()){
            throw new UserNotRegisteredException("Please signup first...");
        }

        // get() is part of the Optional class
        User user = userOptional.get();

        if(!user.getPassword().equals(password)) {
            throw new PasswordMismatchException("Please add correct password...");
        }

        return user;
    }

    @Override
    //pending implementation
    public Boolean validateToken(String token, Long userId) {
        return null;
    }

}
