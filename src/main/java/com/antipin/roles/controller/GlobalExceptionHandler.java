package com.antipin.roles.controller;

import com.antipin.roles.dto.ErrorResponse;
import com.antipin.roles.exception.SignInMaxAttemptsException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDeniedException(AccessDeniedException exception) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ErrorResponse(HttpStatus.UNAUTHORIZED.value(), exception.getMessage()));
    }

    @ExceptionHandler(SignInMaxAttemptsException.class)
    public ResponseEntity<ErrorResponse> handleSignInMaxAttempts(SignInMaxAttemptsException exception) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse(HttpStatus.BAD_REQUEST.value(), exception.getMessage()));
    }
}
