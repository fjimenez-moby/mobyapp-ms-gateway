package com.microservicios.api_gateway.constants;

public final class AuthenticationConstants {

    private AuthenticationConstants() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    // Cookie names
    public static final String SESSION_COOKIE_NAME = "JSESSIONID";

    // Redis keys
    public static final String SPRING_SESSION_KEY_PREFIX = "spring:session:sessions:";
    public static final String SESSION_ATTR_ACCESS_TOKEN = "sessionAttr:accessToken";
    public static final String SESSION_ATTR_REFRESH_TOKEN = "sessionAttr:refreshToken";

    // HTTP Headers
    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String HEADER_BEARER_PREFIX = "Bearer ";
    public static final String HEADER_REFRESH_TOKEN = "X-Refresh-Token";
    public static final String HEADER_CONTENT_TYPE = "application/json";

    // Token validation
    public static final String GOOGLE_TOKEN_PREFIX = "ya29.";

    // Routes
    public static final String ROUTE_AUTH_ME = "/api/auth/me";

    // Error messages
    public static final String MSG_SESSION_NOT_FOUND = "Sesión no encontrada. Por favor, inicie sesión.";
    public static final String MSG_SESSION_INVALID = "Sesión no válida.";
    public static final String MSG_TOKEN_INVALID = "Token de acceso no válido en la sesión.";
    public static final String MSG_SESSION_NOT_IN_REDIS = "Sesión no encontrada en Redis. Por favor, inicie sesión de nuevo.";
}
