package com.example.userauthservice;

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
import com.example.userauthservice.services.AuthService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.MacAlgorithm;
import org.antlr.v4.runtime.misc.Pair;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @InjectMocks
    private AuthService authService;

    @Mock private UserRepo userRepo;
    @Mock private SessionRepo sessionRepo;
    @Mock private PasswordResetTokenRepo passwordResetTokenRepo;
    @Mock private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Mock private KafkaClient kafkaClient;
    @Mock private ObjectMapper objectMapper;

    private SecretKey secretKey;

    @BeforeEach
    void setUp() {
        MacAlgorithm algorithm = Jwts.SIG.HS256;
        secretKey = algorithm.key().build();
        authService.setSecretKey(secretKey);
    }

    // signup
    @Test
    void signup_success_savesAndReturnsUser() throws JsonProcessingException {
        when(userRepo.findByEmail("test@example.com")).thenReturn(Optional.empty());
        when(bCryptPasswordEncoder.encode("pass")).thenReturn("hashed");
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");
        User saved = new User();
        saved.setEmail("test@example.com");
        when(userRepo.save(any(User.class))).thenReturn(saved);

        User result = authService.signup("Alice", "test@example.com", "pass", "1234567890");

        assertNotNull(result);
        verify(kafkaClient).sendMessage(eq("signup"), anyString());
    }

    @Test
    void signup_duplicateEmail_throwsUserAlreadySignedUpException() {
        when(userRepo.findByEmail("dup@example.com")).thenReturn(Optional.of(new User()));

        assertThrows(UserAlreadySignedUpException.class,
                () -> authService.signup("Bob", "dup@example.com", "pass", ""));
        verify(userRepo, never()).save(any());
    }

    // login
    @Test
    void login_success_returnsPairWithToken() {
        User user = userWithId(1L, "user@example.com", "hashed");
        when(userRepo.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(bCryptPasswordEncoder.matches("pass", "hashed")).thenReturn(true);
        when(sessionRepo.save(any(UserSession.class))).thenAnswer(i -> i.getArgument(0));

        Pair<User, String> result = authService.login("user@example.com", "pass");

        assertNotNull(result.a);
        assertNotNull(result.b);
    }

    @Test
    void login_unknownEmail_throwsUserNotRegisteredException() {
        when(userRepo.findByEmail("ghost@example.com")).thenReturn(Optional.empty());

        assertThrows(UserNotRegisteredException.class,
                () -> authService.login("ghost@example.com", "pass"));
    }

    @Test
    void login_wrongPassword_throwsPasswordMismatchException() {
        User user = userWithId(1L, "user@example.com", "hashed");
        when(userRepo.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(bCryptPasswordEncoder.matches("wrong", "hashed")).thenReturn(false);

        assertThrows(PasswordMismatchException.class,
                () -> authService.login("user@example.com", "wrong"));
    }

    // validateToken
    @Test
    void validateToken_sessionNotFound_returnsFalse() {
        when(sessionRepo.findByTokenAndUserId("bad-token", 1L)).thenReturn(Optional.empty());

        assertFalse(authService.validateToken("bad-token", 1L));
    }

    @Test
    void validateToken_validToken_returnsTrue() {
        String token = buildToken(1L, System.currentTimeMillis() + 3_600_000);
        UserSession session = sessionWithToken(token);
        when(sessionRepo.findByTokenAndUserId(token, 1L)).thenReturn(Optional.of(session));

        assertTrue(authService.validateToken(token, 1L));
    }

    @Test
    void validateToken_expiredToken_marksInactiveAndReturnsFalse() {
        String token = buildToken(1L, System.currentTimeMillis() - 1_000);
        UserSession session = sessionWithToken(token);
        when(sessionRepo.findByTokenAndUserId(token, 1L)).thenReturn(Optional.of(session));
        when(sessionRepo.save(any(UserSession.class))).thenAnswer(i -> i.getArgument(0));

        assertFalse(authService.validateToken(token, 1L));
        verify(sessionRepo).save(argThat(s -> s.getStatus() == Status.INACTIVE));
    }

    // getProfile
    @Test
    void getProfile_invalidToken_throwsUnauthorizedException() {
        when(sessionRepo.findByTokenAndUserId("bad", 1L)).thenReturn(Optional.empty());

        assertThrows(UnauthorizedException.class, () -> authService.getProfile(1L, "bad"));
    }

    @Test
    void getProfile_success_returnsUser() {
        String token = buildToken(1L, System.currentTimeMillis() + 3_600_000);
        when(sessionRepo.findByTokenAndUserId(token, 1L)).thenReturn(Optional.of(sessionWithToken(token)));
        User user = userWithId(1L, "u@example.com", "hashed");
        when(userRepo.findById(1L)).thenReturn(Optional.of(user));

        User result = authService.getProfile(1L, token);

        assertEquals("u@example.com", result.getEmail());
    }

    // updateProfile
    @Test
    void updateProfile_invalidToken_throwsUnauthorizedException() {
        when(sessionRepo.findByTokenAndUserId("bad", 2L)).thenReturn(Optional.empty());

        assertThrows(UnauthorizedException.class,
                () -> authService.updateProfile(2L, "bad", "New Name", null));
    }

    @Test
    void updateProfile_success_updatesNameAndPhone() {
        String token = buildToken(2L, System.currentTimeMillis() + 3_600_000);
        when(sessionRepo.findByTokenAndUserId(token, 2L)).thenReturn(Optional.of(sessionWithToken(token)));
        User user = userWithId(2L, "u@example.com", "hashed");
        when(userRepo.findById(2L)).thenReturn(Optional.of(user));
        when(userRepo.save(any(User.class))).thenAnswer(i -> i.getArgument(0));

        User result = authService.updateProfile(2L, token, "New Name", "9999999999");

        assertEquals("New Name", result.getName());
        assertEquals("9999999999", result.getPhoneNumber());
    }

    // forgotPassword
    @Test
    void forgotPassword_unknownEmail_throwsUserNotRegisteredException() {
        when(userRepo.findByEmail("nobody@example.com")).thenReturn(Optional.empty());

        assertThrows(UserNotRegisteredException.class,
                () -> authService.forgotPassword("nobody@example.com"));
    }

    @Test
    void forgotPassword_success_savesTokenAndSendsEmail() throws JsonProcessingException {
        User user = userWithId(1L, "u@example.com", "hashed");
        when(userRepo.findByEmail("u@example.com")).thenReturn(Optional.of(user));
        when(passwordResetTokenRepo.save(any())).thenAnswer(i -> i.getArgument(0));
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        authService.forgotPassword("u@example.com");

        verify(passwordResetTokenRepo).save(argThat(t -> !t.isUsed() && t.getExpiresAt().after(new Date())));
        verify(kafkaClient).sendMessage(eq("password-reset"), anyString());
    }

    // resetPassword
    @Test
    void resetPassword_tokenNotFound_throwsInvalidTokenException() {
        when(passwordResetTokenRepo.findByToken("unknown")).thenReturn(Optional.empty());

        assertThrows(InvalidTokenException.class, () -> authService.resetPassword("unknown", "newPass"));
    }

    @Test
    void resetPassword_alreadyUsedToken_throwsInvalidTokenException() {
        PasswordResetToken rt = resetToken(false /* not expired */, true /* used */);
        when(passwordResetTokenRepo.findByToken("t")).thenReturn(Optional.of(rt));

        assertThrows(InvalidTokenException.class, () -> authService.resetPassword("t", "newPass"));
    }

    @Test
    void resetPassword_expiredToken_throwsInvalidTokenException() {
        PasswordResetToken rt = resetToken(true /* expired */, false);
        when(passwordResetTokenRepo.findByToken("t")).thenReturn(Optional.of(rt));

        assertThrows(InvalidTokenException.class, () -> authService.resetPassword("t", "newPass"));
    }

    @Test
    void resetPassword_success_updatesPasswordAndMarksTokenUsed() {
        User user = userWithId(1L, "u@example.com", "oldHash");
        PasswordResetToken rt = resetToken(false, false);
        rt.setToken("t");
        rt.setUser(user);
        when(passwordResetTokenRepo.findByToken("t")).thenReturn(Optional.of(rt));
        when(bCryptPasswordEncoder.encode("newPass")).thenReturn("newHash");
        when(userRepo.save(any())).thenAnswer(i -> i.getArgument(0));
        when(passwordResetTokenRepo.save(any())).thenAnswer(i -> i.getArgument(0));

        authService.resetPassword("t", "newPass");

        assertEquals("newHash", user.getPassword());
        assertTrue(rt.isUsed());
    }

    // helpers
    private User userWithId(Long id, String email, String password) {
        User u = new User();
        u.setId(id);
        u.setEmail(email);
        u.setPassword(password);
        return u;
    }

    private UserSession sessionWithToken(String token) {
        UserSession s = new UserSession();
        s.setToken(token);
        s.setStatus(Status.ACTIVE);
        return s;
    }

    private String buildToken(Long userId, long expMillis) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", userId);
        claims.put("exp", expMillis);
        return Jwts.builder().claims(claims).signWith(secretKey).compact();
    }

    private PasswordResetToken resetToken(boolean expired, boolean used) {
        PasswordResetToken rt = new PasswordResetToken();
        rt.setExpiresAt(expired
                ? new Date(System.currentTimeMillis() - 1_000)
                : new Date(System.currentTimeMillis() + 900_000));
        rt.setUsed(used);
        return rt;
    }
}
