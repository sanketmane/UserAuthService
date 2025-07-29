package com.example.userauthservice.repos;

import com.example.userauthservice.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
// Remember that repo layer helps in facilitating db operations
public interface UserRepo extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    User save(User user);

}
