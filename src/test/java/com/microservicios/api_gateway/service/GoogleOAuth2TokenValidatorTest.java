package com.microservicios.api_gateway.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class GoogleOAuth2TokenValidatorTest {

    private TokenValidator validator;

    @BeforeEach
    void setUp() {
        validator = new GoogleOAuth2TokenValidator();
    }

    @Test
    void isValid_validGoogleToken_shouldReturnTrue() {
        assertTrue(validator.isValid("ya29.a0AfH6SMBxxxxxxxxxxxxxx"));
    }

    @Test
    void isValid_nullToken_shouldReturnFalse() {
        assertFalse(validator.isValid(null));
    }

    @Test
    void isValid_emptyToken_shouldReturnFalse() {
        assertFalse(validator.isValid(""));
    }

    @Test
    void isValid_blankToken_shouldReturnFalse() {
        assertFalse(validator.isValid("   "));
    }

    @Test
    void isValid_tokenWithoutPrefix_shouldReturnFalse() {
        assertFalse(validator.isValid("invalidtoken123"));
    }

    @Test
    void isValid_wrongPrefix_shouldReturnFalse() {
        assertFalse(validator.isValid("Bearer ya29.tokenxxx"));
    }

    @Test
    void isValid_onlyPrefix_shouldReturnTrue() {
        // Técnicamente válido según nuestra lógica actual
        assertTrue(validator.isValid("ya29."));
    }
}
