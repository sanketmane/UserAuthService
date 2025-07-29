package com.example.userauthservice.exceptions;

public class UserNotRegisteredException extends RuntimeException {
    public UserNotRegisteredException(String message) {
        super(message);
    }
}
