package com.example.userauthservice.controllers;

import com.example.userauthservice.exceptions.PasswordMismatchException;
import com.example.userauthservice.exceptions.UserAlreadySignedUpException;
import com.example.userauthservice.exceptions.UserNotRegisteredException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

// This annotation monitors exceptions mentioned below across the codebase and triggers the
// ExceptionHandler method handleExceptions()
// We will return Exception message in that case, just the HTTP status
@RestControllerAdvice
public class ControllerAdvisor {
    @ExceptionHandler({UserAlreadySignedUpException.class,
                       UserNotRegisteredException.class,
                       PasswordMismatchException.class})
    public ResponseEntity<String> handleExceptions(Exception exception){
        return new ResponseEntity<>(exception.getMessage(), HttpStatus.BAD_REQUEST);
    }
}
