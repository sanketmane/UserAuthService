package com.example.userauthservice.models;

import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ManyToMany;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Entity
public class User extends BaseModel{
    private String name;
    private String password;
    private String email;
    private String phoneNumber;
    // 1 user -> many roles and 1 role -> many users hence M:M
    // hibernate will create user_roles mapping table.
    @ManyToMany
    private List<Role> roles = new ArrayList<>();
}
