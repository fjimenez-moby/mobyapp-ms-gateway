package com.microservicios.api_gateway.config;

import com.microservicios.api_gateway.constants.AuthenticationConstants;
import com.microservicios.api_gateway.util.ErrorResponseBuilder;
import com.microservicios.api_gateway.util.JsonStringCleaner;
import com.microservicios.api_gateway.util.PathMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
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

    private final ReactiveRedisTemplate<String, String> redisTemplate;

    public CustomAuthGatewayFilterFactory(ReactiveRedisTemplate<String, String> redisTemplate) {
        super(Config.class);
        this.redisTemplate = redisTemplate;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String requestPath = exchange.getRequest().getURI().getPath();
            log.info("Recibida solicitud para la URL {}", exchange.getRequest().getURI());

            // Verificar si la ruta está excluida del filtro de autenticación
            if (config.getExcludePaths() != null) {
                for (String excludePath : config.getExcludePaths()) {
                    if (PathMatcher.matches(requestPath, excludePath)) {
                        log.info("Ruta excluida del filtro de autenticación: {}", requestPath);
                        return chain.filter(exchange);
                    }
                }
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

            // Spring Session codifica el sessionId en Base64 para la cookie
            String sessionId;
            try {
                sessionId = new String(Base64.getDecoder().decode(encodedSessionId));
                log.info("SessionId decodificado: {}", sessionId);
            } catch (Exception e) {
                log.warn("Error al decodificar sessionId: {}", e.getMessage());
                return unauthorizedResponse(requestPath,exchange, AuthenticationConstants.MSG_SESSION_INVALID);
            }

            // Buscamos en Redis con el prefijo de Spring Session
            String springSessionKey = AuthenticationConstants.SPRING_SESSION_KEY_PREFIX + sessionId;

            return redisTemplate.opsForHash()
                    .get(springSessionKey, AuthenticationConstants.SESSION_ATTR_ACCESS_TOKEN)
                    .switchIfEmpty(Mono.error(new RuntimeException("AccessToken no encontrado en sesión")))
                    .flatMap(accessTokenObj -> {
                        String accessToken = JsonStringCleaner.removeQuotes(accessTokenObj.toString());
                        final String finalAccessToken = accessToken;

                        if (finalAccessToken == null || finalAccessToken.trim().isEmpty() || !finalAccessToken.startsWith(AuthenticationConstants.GOOGLE_TOKEN_PREFIX)) {
                            log.warn("AccessToken no válido en la sesión Redis. Token: {}", finalAccessToken);
                            return unauthorizedResponse(requestPath,exchange, AuthenticationConstants.MSG_TOKEN_INVALID);
                        }

                        log.info("AccessToken limpio extraído: {}", finalAccessToken.length() > 20 ? finalAccessToken.substring(0, 20) + "..." : finalAccessToken);

                        return redisTemplate.opsForHash()
                                .get(springSessionKey, AuthenticationConstants.SESSION_ATTR_REFRESH_TOKEN)
                                .defaultIfEmpty("")
                                .flatMap(refreshTokenObj -> {
                                    String refreshToken = JsonStringCleaner.removeQuotes(refreshTokenObj.toString());
                                    log.info("Refresh token: {}", refreshToken);

                                    final String finalRefreshToken = refreshToken;

                                    ServerWebExchange mutatedExchange = exchange.mutate()
                                            .request(builder -> {
                                                builder.header(AuthenticationConstants.HEADER_AUTHORIZATION, AuthenticationConstants.HEADER_BEARER_PREFIX + finalAccessToken);
                                                if (finalRefreshToken != null && !finalRefreshToken.trim().isEmpty()) {
                                                    builder.header(AuthenticationConstants.HEADER_REFRESH_TOKEN, finalRefreshToken);
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

    public static class Config {
        private List<String> excludePaths;

        public List<String> getExcludePaths() {
            return excludePaths;
        }

        public void setExcludePaths(List<String> excludePaths) {
            this.excludePaths = excludePaths;
        }
    }
}