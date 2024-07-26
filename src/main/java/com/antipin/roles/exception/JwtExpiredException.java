package com.antipin.roles.exception;

public class JwtExpiredException extends RuntimeException {

    public JwtExpiredException() {
        super("JWT has expired");
    }
}
