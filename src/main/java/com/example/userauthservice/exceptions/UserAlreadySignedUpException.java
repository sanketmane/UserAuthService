package com.example.userauthservice.exceptions;

public class UserAlreadySignedUpException extends RuntimeException {
    public UserAlreadySignedUpException(String message) {
        super(message);
    }
}
