package com.microservicios.api_gateway.repository;

import reactor.core.publisher.Mono;

public interface SessionRepository {

    Mono<String> getAccessToken(String sessionId);

    Mono<String> getRefreshToken(String sessionId);
}
