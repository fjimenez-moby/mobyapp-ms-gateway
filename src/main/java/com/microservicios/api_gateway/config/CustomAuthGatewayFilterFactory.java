package com.microservicios.api_gateway.config;

import com.microservicios.api_gateway.constants.AuthenticationConstants;
import com.microservicios.api_gateway.repository.SessionRepository;
import com.microservicios.api_gateway.util.ErrorResponseBuilder;
import com.microservicios.api_gateway.util.PathMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import java.util.Base64;
import java.util.List;

@Component
public class CustomAuthGatewayFilterFactory extends AbstractGatewayFilterFactory<CustomAuthGatewayFilterFactory.Config> {

    private static final Logger log = LoggerFactory.getLogger(CustomAuthGatewayFilterFactory.class);

    private final SessionRepository sessionRepository;

    public CustomAuthGatewayFilterFactory(SessionRepository sessionRepository) {
        super(Config.class);
        this.sessionRepository = sessionRepository;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String requestPath = exchange.getRequest().getURI().getPath();
            log.info("Recibida solicitud para la URL {}", exchange.getRequest().getURI());

            // Verificar si la ruta está excluida del filtro de autenticación
            if (isPathExcluded(requestPath, config)) {
                log.info("Ruta excluida del filtro de autenticación: {}", requestPath);
                return chain.filter(exchange);
            }

            //Lee cookie automatica del navegador
            HttpCookie sessionCookie = exchange.getRequest()
                    .getCookies().getFirst(AuthenticationConstants.SESSION_COOKIE_NAME);



            if (sessionCookie == null) {
                log.warn("Petición rechazada: cookie JSESSIONID ausente. Usuario no autenticado.");
                return unauthorizedResponse(requestPath,exchange, AuthenticationConstants.MSG_SESSION_NOT_FOUND);
            }

            // Extraemos el sessionId de la cookie (Spring Session lo genera automáticamente)
            String encodedSessionId = sessionCookie.getValue();
            log.info("SessionId codificado encontrado en cookie: {}", encodedSessionId);

            String sessionId;
            try {
                sessionId = decodeSessionId(encodedSessionId);
                log.info("SessionId decodificado: {}", sessionId);
            } catch (IllegalArgumentException e) {
                return unauthorizedResponse(requestPath, exchange, AuthenticationConstants.MSG_SESSION_INVALID);
            }

            return sessionRepository.getAccessToken(sessionId)
                    .switchIfEmpty(Mono.error(new RuntimeException("AccessToken no encontrado en sesión")))
                    .flatMap(accessToken -> {
                        if (!isValidAccessToken(accessToken)) {
                            log.warn("AccessToken no válido en la sesión Redis. Token: {}", accessToken);
                            return unauthorizedResponse(requestPath, exchange, AuthenticationConstants.MSG_TOKEN_INVALID);
                        }

                        log.info("AccessToken limpio extraído: {}", accessToken.length() > 20 ? accessToken.substring(0, 20) + "..." : accessToken);

                        return sessionRepository.getRefreshToken(sessionId)
                                .flatMap(refreshToken -> {
                                    log.info("Refresh token: {}", refreshToken);

                                    ServerWebExchange mutatedExchange = exchange.mutate()
                                            .request(builder -> {
                                                builder.header(AuthenticationConstants.HEADER_AUTHORIZATION, AuthenticationConstants.HEADER_BEARER_PREFIX + accessToken);
                                                if (refreshToken != null && !refreshToken.trim().isEmpty()) {
                                                    builder.header(AuthenticationConstants.HEADER_REFRESH_TOKEN, refreshToken);
                                                }
                                            })
                                            .build();

                                    log.info("Token inyectado correctamente al microservicio");
                                    return chain.filter(mutatedExchange);
                                });
                    })
                    .onErrorResume(error -> {
                        log.warn("Error al procesar sesión: {}", error.getMessage());
                        return unauthorizedResponse(requestPath, exchange, AuthenticationConstants.MSG_SESSION_NOT_IN_REDIS);
                    });
        };
    }

    private Mono<Void> unauthorizedResponse(String requestPath, ServerWebExchange exchange, String message) {
        HttpStatus status = PathMatcher.matches(requestPath, AuthenticationConstants.ROUTE_AUTH_ME)
            ? HttpStatus.FORBIDDEN
            : HttpStatus.UNAUTHORIZED;
        return ErrorResponseBuilder.buildErrorResponse(exchange.getResponse(), status, message);
    }

    private boolean isPathExcluded(String requestPath, Config config) {
        if (config.excludePaths() == null) {
            return false;
        }
        for (String excludePath : config.excludePaths()) {
            if (PathMatcher.matches(requestPath, excludePath)) {
                return true;
            }
        }
        return false;
    }

    private String decodeSessionId(String encodedSessionId) {
        try {
            return new String(Base64.getDecoder().decode(encodedSessionId));
        } catch (Exception e) {
            log.warn("Error al decodificar sessionId: {}", e.getMessage());
            throw new IllegalArgumentException("Invalid session ID encoding", e);
        }
    }

    private boolean isValidAccessToken(String accessToken) {
        return accessToken != null &&
               !accessToken.trim().isEmpty() &&
               accessToken.startsWith(AuthenticationConstants.GOOGLE_TOKEN_PREFIX);
    }

    public record Config(List<String> excludePaths) {
    }
}