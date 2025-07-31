package com.example.userauthservice.services;

import com.example.userauthservice.exceptions.PasswordMismatchException;
import com.example.userauthservice.exceptions.UserAlreadySignedUpException;
import com.example.userauthservice.exceptions.UserNotRegisteredException;
import com.example.userauthservice.models.User;
import com.example.userauthservice.repos.UserRepo;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;
import org.antlr.v4.runtime.misc.Pair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class AuthService implements IAuthService {

    @Autowired
    private UserRepo userRepo;

    // BCryptPasswordEncoder needs spring-boot-starter-security dependency installed in pom.xml
    // By default, when you Autowire BCryptPasswordEncoder object below, IntelliJ will complain
    // This is because the dependency for it for some reason isn't being satisfied.
    // To solve, we need to declare it as a Bean by adding it to a custom config class called
    // "SecurityConfig" created in a "config" package.
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public User signup(String name, String email, String password, String phoneNumber) {
        if (userRepo.findByEmail(email).isPresent()) {
            throw new UserAlreadySignedUpException("Please login directly");
        }

        User user = new User();
        user.setEmail(email);
        user.setPassword(bCryptPasswordEncoder.encode(password)); // save encrypted password in DB.
        user.setName(name);
        user.setPhoneNumber(phoneNumber);
        return userRepo.save(user);
    }

    @Override
    public Pair<User, String> login(String email, String password){
        Optional<User> userOptional = userRepo.findByEmail(email);
        if(userOptional.isEmpty()){
            throw new UserNotRegisteredException("Please signup first...");
        }

        // get() is part of the Optional class
        User user = userOptional.get();

//        if(!user.getPassword().equals(password)) {
        if (!bCryptPasswordEncoder.matches(password, user.getPassword())) {
            throw new PasswordMismatchException("Please add correct password...");
        }

        // For JWT token generation, need to install the following maven dependencies:
        // 1. jjwt-api
        // 2. jjwt-impl
        // 3. jjwt-jackson
        // Remember JWT consists of Hashing algo+Payload+Secret

        // Hardcoded payload used for testing
        //        String message = "{\n" +
//                "   \"email\": \"optimus@gmail.com\",\n" +
//                "   \"roles\": [\n" +
//                "      \"instructor\",\n" +
//                "      \"ta\"\n" +
//                "   ],\n" +
//                "   \"expirationDate\": \"2ndApril2026\"\n" +
//                "}";
//
//        byte[] content = message.getBytes(StandardCharsets.UTF_8);

        // Claims basically means payload
        Map<String,Object> claims = new HashMap<String,Object>();
        claims.put("iss", "scaler");
        claims.put("id", user.getId());
        claims.put("access", user.getRoles());
        Long currentTimeMillis = System.currentTimeMillis(); // even it says millisecond, return val is seconds
        claims.put("gen", currentTimeMillis);
        claims.put("exp", currentTimeMillis+3600); // expiration = current time + 1hr

        MacAlgorithm algorithm = Jwts.SIG.HS256; // Hashing algo
        SecretKey secretKey = algorithm.key().build(); // Secret

        // Since we have all 3 items i.e. Hashing algo+Payload+Secret
        // lets build the token now
        String token = Jwts.builder().claims(claims).signWith(secretKey).compact();
        return new Pair<User,String>(user, token); // we want to return both user, token in same object
    }

    @Override
    //pending implementation
    public Boolean validateToken(String token, Long userId) {
        return null;
    }

}
