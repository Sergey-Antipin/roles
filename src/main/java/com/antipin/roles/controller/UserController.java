package com.antipin.roles.controller;

import com.antipin.roles.dto.SignInRequest;
import com.antipin.roles.model.User;
import com.antipin.roles.model.UserPrincipal;
import com.antipin.roles.security.JwtUtil;
import com.antipin.roles.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
@RequiredArgsConstructor
@RequestMapping("/")
public class UserController {

    private final UserService userService;

    private final AuthenticationManager authenticationManager;

    private final JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<User> signIn(@RequestBody SignInRequest request) {
        Authentication authRequest;
        String principal = request.getUsername();
        String credentials = request.getPassword();
        try {
            authRequest = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(principal, credentials));
        } catch (BadCredentialsException e) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        UserPrincipal user = (UserPrincipal) authRequest.getPrincipal();
        SecurityContextHolder.getContext().setAuthentication(authRequest);
        return ResponseEntity.ok()
                .header(HttpHeaders.AUTHORIZATION, jwtUtil.generateToken(user))
                .body(userService.getByUsername(user.getUsername()));
    }

    @GetMapping("/users")
    public ResponseEntity<String> forUsers(Principal principal) {
        return ResponseEntity.ok("users");
    }

    @GetMapping("/moderators")
    public ResponseEntity<String> forModerators(Principal principal) {
        return ResponseEntity.ok("moderators");
    }

    @GetMapping("/admins")
    public ResponseEntity<String> forAdmins(Principal principal) {
        return ResponseEntity.ok("admins");
    }
}
