package com.example.userauthservice;

import com.example.userauthservice.controllers.AuthController;
import com.example.userauthservice.dtos.*;
import com.example.userauthservice.exceptions.InvalidTokenException;
import com.example.userauthservice.exceptions.UnauthorizedException;
import com.example.userauthservice.models.User;
import com.example.userauthservice.services.IAuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.antlr.v4.runtime.misc.Pair;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(
        controllers = AuthController.class,
        excludeAutoConfiguration = {SecurityAutoConfiguration.class, SecurityFilterAutoConfiguration.class}
)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private IAuthService authService;

    @Autowired
    private ObjectMapper objectMapper;

    // signup
    @Test
    void signup_returnsUserDto() throws Exception {
        User user = userWithId(1L, "alice@example.com", "Alice");
        when(authService.signup(anyString(), anyString(), anyString(), anyString())).thenReturn(user);

        SignUpRequestDto body = new SignUpRequestDto();
        body.setName("Alice");
        body.setEmail("alice@example.com");
        body.setPassword("pass");
        body.setPhoneNumber("1234567890");

        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("alice@example.com"))
                .andExpect(jsonPath("$.username").value("Alice"));
    }

    // login
    @Test
    void login_returnsUserDto() throws Exception {
        User user = userWithId(1L, "alice@example.com", "Alice");
        // use a minimal valid cookie string so the servlet layer does not reject the header
        when(authService.login("alice@example.com", "pass")).thenReturn(new Pair<>(user, "session=jwt-token"));

        LoginRequestDto body = new LoginRequestDto();
        body.setEmail("alice@example.com");
        body.setPassword("pass");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("alice@example.com"));
    }

    // validateToken
    @Test
    void validateToken_valid_returnsTrue() throws Exception {
        when(authService.validateToken("tok", 1L)).thenReturn(true);

        ValidateTokenRequestDto body = new ValidateTokenRequestDto();
        body.setToken("tok");
        body.setUserId(1L);

        mockMvc.perform(post("/api/auth/validateToken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isOk())
                .andExpect(content().string("true"));
    }

    @Test
    void validateToken_invalid_returns401() throws Exception {
        when(authService.validateToken("bad", 1L)).thenReturn(false);

        ValidateTokenRequestDto body = new ValidateTokenRequestDto();
        body.setToken("bad");
        body.setUserId(1L);

        mockMvc.perform(post("/api/auth/validateToken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isUnauthorized());
    }

    // getProfile
    @Test
    void getProfile_success_returnsUserDto() throws Exception {
        User user = userWithId(1L, "alice@example.com", "Alice");
        when(authService.getProfile(1L, "valid-token")).thenReturn(user);

        mockMvc.perform(get("/api/auth/profile/1")
                        .header("token", "valid-token"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("alice@example.com"));
    }

    @Test
    void getProfile_invalidToken_returns401() throws Exception {
        when(authService.getProfile(1L, "bad")).thenThrow(new UnauthorizedException("Please login again!"));

        mockMvc.perform(get("/api/auth/profile/1")
                        .header("token", "bad"))
                .andExpect(status().isUnauthorized());
    }

    // updateProfile
    @Test
    void updateProfile_success_returnsUpdatedUserDto() throws Exception {
        User user = userWithId(1L, "alice@example.com", "Alice Updated");
        user.setPhoneNumber("9999999999");
        when(authService.updateProfile(eq(1L), eq("valid-token"), anyString(), anyString())).thenReturn(user);

        UpdateProfileRequestDto body = new UpdateProfileRequestDto();
        body.setName("Alice Updated");
        body.setPhoneNumber("9999999999");

        mockMvc.perform(put("/api/auth/profile/1")
                        .header("token", "valid-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("Alice Updated"))
                .andExpect(jsonPath("$.phoneNumber").value("9999999999"));
    }

    // forgotPassword
    @Test
    void forgotPassword_success_returns200() throws Exception {
        doNothing().when(authService).forgotPassword("alice@example.com");

        ForgotPasswordRequestDto body = new ForgotPasswordRequestDto();
        body.setEmail("alice@example.com");

        mockMvc.perform(post("/api/auth/forgot-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isOk());
    }

    // resetPassword
    @Test
    void resetPassword_success_returns200() throws Exception {
        doNothing().when(authService).resetPassword("valid-token", "newPass");

        ResetPasswordRequestDto body = new ResetPasswordRequestDto();
        body.setToken("valid-token");
        body.setNewPassword("newPass");

        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isOk());
    }

    @Test
    void resetPassword_invalidToken_returns400() throws Exception {
        doThrow(new InvalidTokenException("Invalid token")).when(authService).resetPassword("bad", "newPass");

        ResetPasswordRequestDto body = new ResetPasswordRequestDto();
        body.setToken("bad");
        body.setNewPassword("newPass");

        mockMvc.perform(post("/api/auth/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest());
    }

    // helpers
    private User userWithId(Long id, String email, String name) {
        User u = new User();
        u.setId(id);
        u.setEmail(email);
        u.setName(name);
        return u;
    }
}
