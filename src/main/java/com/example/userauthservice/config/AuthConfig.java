package com.example.userauthservice.config;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.SecretKey;

@Configuration
public class AuthConfig {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // The below code snippet needs to be added because
    // the spring-boot-starter-security dependency brings up a default login page
    // which causes wrong response to be sent after making API call from postman
    // Adding the below turns off that default behavior of adding login page.

// Commenting out the below implementation of SecurityFilterChain as it blocks loading of Spring Auth server
    // which also has its own implementation of SecurityFilterChain in SecurityConfig class
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
//        httpSecurity.cors().disable();
//        httpSecurity.csrf().disable();
//        httpSecurity.authorizeHttpRequests(authorize->authorize.anyRequest().permitAll());
//        return httpSecurity.build();
//    }


    @Bean
    public SecretKey secretKey() {
        MacAlgorithm algorithm = Jwts.SIG.HS256; // Hashing algo
        SecretKey secretKey = algorithm.key().build(); // Secret
        return secretKey;
    }
}
