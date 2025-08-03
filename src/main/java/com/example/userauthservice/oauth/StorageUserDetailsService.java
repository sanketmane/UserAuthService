package com.example.userauthservice.oauth;

import com.example.userauthservice.models.User;
import com.example.userauthservice.repos.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

// This service will get the user details from db
@Service
public class StorageUserDetailsService implements UserDetailsService  {

    @Autowired
    private UserRepo userRepo;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Optional<User> userOptional = userRepo.findByEmail(email);

        if(userOptional.isEmpty()) {
            throw new UsernameNotFoundException("User not found");
        }

        return new StorageUserDetails(userOptional.get());
    }
}