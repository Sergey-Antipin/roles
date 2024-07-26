package com.antipin.roles.controller;

import com.antipin.roles.exception.SignInMaxAttemptsException;
import com.antipin.roles.service.LoginAttemptService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
public class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private LoginAttemptService loginAttemptService;

    @Value("${signin.max.attempts}")
    private int maxSignInAttempts;

    private final String AUTH_HEADER = "Authorization";
    private final String AUTH_HEADER_PREFIX = "Bearer ";

    private final String correctCredentials = """
            {
                "username": "moderator",
                "password": "moderatorpassword"
            }
            """;
    private final String incorrectCredentials = """
            {
                "username": "moderator",
                "password": "wrongpassword"
            }
            """;

    @Test
    public void whenLoginWithRightCredentialsThenReturnTokenAndAccessByJwt() throws Exception {
        MvcResult result = mockMvc.perform(post("/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(correctCredentials)
                        .secure(true))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(header().exists(AUTH_HEADER))
                .andReturn();
        String token = result.getResponse().getHeader(AUTH_HEADER);
        mockMvc.perform(get("/moderators")
                        .header(AUTH_HEADER, AUTH_HEADER_PREFIX.concat(token))
                        .secure(true))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    public void whenLoginWithWrongCredentialsThenReturnUnauthorized() throws Exception {
        mockMvc.perform(post("/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(incorrectCredentials)
                        .secure(true))
                .andDo(print())
                .andExpect(status().isUnauthorized())
                .andExpect(header().doesNotExist(AUTH_HEADER));
    }

    @Test
    @WithMockUser(username = "user", password = "password")
    public void whenSignedInAsUserThenAccessAllowedOnlyToUsersResources() throws Exception {
        mockMvc.perform(get("/users")
                        .secure(true))
                .andDo(print())
                .andExpect(status().isOk());
        mockMvc.perform(get("/moderators")
                        .secure(true))
                .andDo(print())
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/admins")
                        .secure(true))
                .andDo(print())
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "moderator", password = "moderatorpassword", roles = "MODERATOR")
    public void whenSignedInAsModeratorThenAccessAllowedToModeratorsAndImpliedResources() throws Exception {
        mockMvc.perform(get("/users")
                        .secure(true))
                .andDo(print())
                .andExpect(status().isOk());
        mockMvc.perform(get("/moderators")
                        .secure(true))
                .andDo(print())
                .andExpect(status().isOk());
        mockMvc.perform(get("/admins")
                        .secure(true))
                .andDo(print())
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin", password = "adminpassword", roles = "ADMIN")
    public void whenSignedInAsAdminThenAccessAllowedToAllResources() throws Exception {
        mockMvc.perform(get("/users")
                        .secure(true))
                .andDo(print())
                .andExpect(status().isOk());
        mockMvc.perform(get("/moderators")
                        .secure(true))
                .andDo(print())
                .andExpect(status().isOk());
        mockMvc.perform(get("/admins")
                        .secure(true))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    public void whenAuthenticationFailureCountExceededThenForbidSigningInForOneDay() throws Exception {
        loginAttemptService.invalidateCache();
        for (int i = 0; i < maxSignInAttempts; i++) {
            mockMvc.perform(post("/login")
                            .secure(true)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(incorrectCredentials))
                    .andDo(print())
                    .andExpect(status().isUnauthorized());
        }
        mockMvc.perform(post("/login")
                        .secure(true)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(correctCredentials))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(new SignInMaxAttemptsException().getMessage()));
    }
}
