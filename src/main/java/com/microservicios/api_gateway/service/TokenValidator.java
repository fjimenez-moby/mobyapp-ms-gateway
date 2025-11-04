package com.microservicios.api_gateway.service;

public interface TokenValidator {

    boolean isValid(String token);
}
