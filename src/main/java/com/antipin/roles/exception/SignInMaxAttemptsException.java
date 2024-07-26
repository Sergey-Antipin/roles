package com.antipin.roles.exception;

public class SignInMaxAttemptsException extends RuntimeException {

    public SignInMaxAttemptsException() {
        super("You have reached max sign in attempts per day. Try later...");
    }
}
