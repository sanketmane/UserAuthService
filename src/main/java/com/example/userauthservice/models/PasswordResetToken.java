package com.example.userauthservice.models;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.ManyToOne;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@Entity
public class PasswordResetToken extends BaseModel {

    @Column(unique = true)
    private String token;

    @ManyToOne
    private User user;

    private Date expiresAt;

    // single-use flag
    private boolean used;
}
