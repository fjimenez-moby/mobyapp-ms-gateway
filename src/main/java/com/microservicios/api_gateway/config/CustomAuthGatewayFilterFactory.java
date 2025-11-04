package com.microservicios.api_gateway.config;

import com.microservicios.api_gateway.constants.AuthenticationConstants;
import com.microservicios.api_gateway.util.ErrorResponseBuilder;
import com.microservicios.api_gateway.util.JsonStringCleaner;
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
import java.util.logging.Logger;

@Component
public class CustomAuthGatewayFilterFactory extends AbstractGatewayFilterFactory<CustomAuthGatewayFilterFactory.Config> {

    private final ReactiveRedisTemplate<String, String> redisTemplate;

    private static final Logger logger = Logger.getLogger(CustomAuthGatewayFilterFactory.class.getName());

    public CustomAuthGatewayFilterFactory(ReactiveRedisTemplate<String, String> redisTemplate) {
        super(Config.class);
        this.redisTemplate = redisTemplate;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String requestPath = exchange.getRequest().getURI().getPath();
            logger.info("Recibida solicitud para la URL " + exchange.getRequest().getURI());

            // Verificar si la ruta está excluida del filtro de autenticación
            if (config.getExcludePaths() != null) {
                for (String excludePath : config.getExcludePaths()) {
                    if (pathMatches(requestPath, excludePath)) {
                        logger.info("Ruta excluida del filtro de autenticación: " + requestPath);
                        return chain.filter(exchange);
                    }
                }
            }

            //Lee cookie automatica del navegador
            HttpCookie sessionCookie = exchange.getRequest()
                    .getCookies().getFirst(AuthenticationConstants.SESSION_COOKIE_NAME);



            if (sessionCookie == null) {
                logger.warning("Petición rechazada: cookie JSESSIONID ausente. Usuario no autenticado.");
                return unauthorizedResponse(requestPath,exchange, AuthenticationConstants.MSG_SESSION_NOT_FOUND);
            }

            // Extraemos el sessionId de la cookie (Spring Session lo genera automáticamente)
            String encodedSessionId = sessionCookie.getValue();
            logger.info("SessionId codificado encontrado en cookie: " + encodedSessionId);

            // Spring Session codifica el sessionId en Base64 para la cookie
            String sessionId;
            try {
                sessionId = new String(Base64.getDecoder().decode(encodedSessionId));
                logger.info("SessionId decodificado: " + sessionId);
            } catch (Exception e) {
                logger.warning("Error al decodificar sessionId: " + e.getMessage());
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
                            logger.warning("AccessToken no válido en la sesión Redis. Token: " + finalAccessToken);
                            return unauthorizedResponse(requestPath,exchange, AuthenticationConstants.MSG_TOKEN_INVALID);
                        }

                        logger.info("AccessToken limpio extraído: " + (finalAccessToken.length() > 20 ? finalAccessToken.substring(0, 20) + "..." : finalAccessToken));

                        return redisTemplate.opsForHash()
                                .get(springSessionKey, AuthenticationConstants.SESSION_ATTR_REFRESH_TOKEN)
                                .defaultIfEmpty("")
                                .flatMap(refreshTokenObj -> {
                                    String refreshToken = JsonStringCleaner.removeQuotes(refreshTokenObj.toString());
                                    logger.info("Refresh token: " + refreshToken);

                                    final String finalRefreshToken = refreshToken;

                                    ServerWebExchange mutatedExchange = exchange.mutate()
                                            .request(builder -> {
                                                builder.header(AuthenticationConstants.HEADER_AUTHORIZATION, AuthenticationConstants.HEADER_BEARER_PREFIX + finalAccessToken);
                                                if (finalRefreshToken != null && !finalRefreshToken.trim().isEmpty()) {
                                                    builder.header(AuthenticationConstants.HEADER_REFRESH_TOKEN, finalRefreshToken);
                                                }
                                            })
                                            .build();

                                    logger.info("Token inyectado correctamente al microservicio");
                                    return chain.filter(mutatedExchange);
                                });
                    })
                    .onErrorResume(error -> {
                        logger.warning("Error al procesar sesión: " + error.getMessage());
                        return unauthorizedResponse(requestPath, exchange, AuthenticationConstants.MSG_SESSION_NOT_IN_REDIS);
                    });
        };
    }

    private Mono<Void> unauthorizedResponse(String requestPath, ServerWebExchange exchange, String message) {
        HttpStatus status = pathMatches(requestPath, AuthenticationConstants.ROUTE_AUTH_ME)
            ? HttpStatus.FORBIDDEN
            : HttpStatus.UNAUTHORIZED;
        return ErrorResponseBuilder.buildErrorResponse(exchange.getResponse(), status, message);
    }


    // Método para verificar si una ruta coincide con un patrón (soporta **)
    private boolean pathMatches(String requestPath, String pattern) {
        // Si el patrón termina con /**, verificar si el path empieza con la base
        if (pattern.endsWith("/**")) {
            String basePath = pattern.substring(0, pattern.length() - 3);
            return requestPath.startsWith(basePath);
        }
        // Coincidencia exacta
        return requestPath.equals(pattern);
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