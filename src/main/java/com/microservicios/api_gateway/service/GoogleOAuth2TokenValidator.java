package com.microservicios.api_gateway.service;

import com.microservicios.api_gateway.constants.AuthenticationConstants;
import org.springframework.stereotype.Service;

@Service
public class GoogleOAuth2TokenValidator implements TokenValidator {

    @Override
    public boolean isValid(String token) {
        return token != null &&
               !token.trim().isEmpty() &&
               token.startsWith(AuthenticationConstants.GOOGLE_TOKEN_PREFIX);
    }
}
