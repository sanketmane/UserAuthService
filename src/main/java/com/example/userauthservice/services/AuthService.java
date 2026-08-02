package com.example.userauthservice.services;

import com.example.userauthservice.clients.KafkaClient;
import com.example.userauthservice.dtos.EmailDto;
import com.example.userauthservice.exceptions.InvalidTokenException;
import com.example.userauthservice.exceptions.PasswordMismatchException;
import com.example.userauthservice.exceptions.UnauthorizedException;
import com.example.userauthservice.exceptions.UserAlreadySignedUpException;
import com.example.userauthservice.exceptions.UserNotRegisteredException;
import com.example.userauthservice.models.PasswordResetToken;
import com.example.userauthservice.models.Status;
import com.example.userauthservice.models.User;
import com.example.userauthservice.models.UserSession;
import com.example.userauthservice.repos.PasswordResetTokenRepo;
import com.example.userauthservice.repos.SessionRepo;
import com.example.userauthservice.repos.UserRepo;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;
import org.antlr.v4.runtime.misc.Pair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
public class AuthService implements IAuthService {

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private SessionRepo sessionRepo;

    @Autowired
    private SecretKey secretKey;

    // visible for testing
    public void setSecretKey(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    @Autowired
    private KafkaClient kafkaClient;

    @Autowired
    private PasswordResetTokenRepo passwordResetTokenRepo;

    // BCryptPasswordEncoder needs spring-boot-starter-security dependency installed in pom.xml
    // By default, when you Autowire BCryptPasswordEncoder object below, IntelliJ will complain
    // This is because the dependency for it for some reason isn't being satisfied.
    // To solve, we need to declare it as a Bean by adding it to a custom config class called
    // "SecurityConfig" created in a "config" package.
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private ObjectMapper objectMapper;

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

        // send message via kafka to EmailService
        try {
            EmailDto emailDto = new EmailDto();
            emailDto.setFrom("anuragonhiring@gmail.com");
            emailDto.setTo(email);
            emailDto.setSubject("Welcome!");
            emailDto.setBody("Have a nice day!");
            kafkaClient.sendMessage("signup", objectMapper.writeValueAsString(emailDto));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e.getMessage());
        }
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

//        MacAlgorithm algorithm = Jwts.SIG.HS256; // Hashing algo
//        SecretKey secretKey = algorithm.key().build(); // Secret

        // Since we have all 3 items i.e. Hashing algo+Payload+Secret
        // lets build the token now
        String token = Jwts.builder().claims(claims).signWith(secretKey).compact();
        UserSession userSession = new UserSession();
        userSession.setToken(token);
        userSession.setUser(user);
        userSession.setStatus(Status.ACTIVE);
        sessionRepo.save(userSession);

        return new Pair<User,String>(user, token); // we want to return both user, token in same object
    }

    @Override
    //pending implementation
    public Boolean validateToken(String token, Long userId) {
        Optional<UserSession> optionalUserSession = sessionRepo.findByTokenAndUserId(token, userId);
        if(optionalUserSession.isEmpty()){
            return false;
        }

        // We will do reverse engineering here
        // From secret, we will try to find out the payload
        // We will also check if the existing token is valid or expired
        JwtParser jwtParser = Jwts.parser().verifyWith(secretKey).build(); // build the jwt parser
        Claims claims = jwtParser.parseSignedClaims(token).getPayload(); // get the payload using the parser

        Long tokenExpiresIn = (Long) claims.get("exp"); // get the token expiry time
        Long currentTime = System.currentTimeMillis(); // get the current time

        // validate if the token is valid or expired
        // if expired, update the session info to mark the token as inactive in db.
        // and return the status as false, otherwise return true
        if(tokenExpiresIn < currentTime){
            System.out.println("token expired");
            UserSession userSession = optionalUserSession.get();
            userSession.setStatus(Status.INACTIVE);
            sessionRepo.save(userSession);
            return false;
        }
        return true;

    }

    @Override
    public User getProfile(Long userId, String token) {
        if (!validateToken(token, userId)) {
            throw new UnauthorizedException("Please login again!");
        }
        return userRepo.findById(userId)
                .orElseThrow(() -> new UserNotRegisteredException("User not found."));
    }

    @Override
    public User updateProfile(Long userId, String token, String name, String phoneNumber) {
        if (!validateToken(token, userId)) {
            throw new UnauthorizedException("Please login again!");
        }
        User user = userRepo.findById(userId)
                .orElseThrow(() -> new UserNotRegisteredException("User not found."));
        if (name != null && !name.isBlank()) user.setName(name);
        if (phoneNumber != null && !phoneNumber.isBlank()) user.setPhoneNumber(phoneNumber);
        return userRepo.save(user);
    }

    @Override
    public void forgotPassword(String email) {
        Optional<User> userOptional = userRepo.findByEmail(email);
        if (userOptional.isEmpty()) {
            throw new UserNotRegisteredException("No account found for this email.");
        }
        User user = userOptional.get();

        PasswordResetToken resetToken = new PasswordResetToken();
        resetToken.setToken(UUID.randomUUID().toString());
        resetToken.setUser(user);
        resetToken.setExpiresAt(new Date(System.currentTimeMillis() + 15 * 60 * 1000));
        resetToken.setUsed(false);
        passwordResetTokenRepo.save(resetToken);

        try {
            EmailDto emailDto = new EmailDto();
            emailDto.setFrom("sanket.mane@gmail.com");
            emailDto.setTo(email);
            emailDto.setSubject("Password Reset Request");
            emailDto.setBody("Click to reset your password: http://localhost:3000/reset-password?token=" + resetToken.getToken());
            kafkaClient.sendMessage("password-reset", objectMapper.writeValueAsString(emailDto));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    @Override
    public void resetPassword(String token, String newPassword) {
        Optional<PasswordResetToken> tokenOptional = passwordResetTokenRepo.findByToken(token);
        if (tokenOptional.isEmpty()) {
            throw new InvalidTokenException("Invalid password reset token.");
        }
        PasswordResetToken resetToken = tokenOptional.get();
        if (resetToken.isUsed()) {
            throw new InvalidTokenException("Password reset token has already been used.");
        }
        if (resetToken.getExpiresAt().before(new Date())) {
            throw new InvalidTokenException("Password reset token has expired.");
        }
        User user = resetToken.getUser();
        user.setPassword(bCryptPasswordEncoder.encode(newPassword));
        userRepo.save(user);
        resetToken.setUsed(true);
        passwordResetTokenRepo.save(resetToken);
    }

}
