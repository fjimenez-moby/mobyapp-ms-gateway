package com.microservicios.api_gateway.util;

import com.microservicios.api_gateway.constants.AuthenticationConstants;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import reactor.core.publisher.Mono;

public final class ErrorResponseBuilder {

    private ErrorResponseBuilder() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    public static Mono<Void> buildErrorResponse(ServerHttpResponse response, HttpStatus status, String message) {
        response.setStatusCode(status);
        response.getHeaders().add("Content-Type", AuthenticationConstants.HEADER_CONTENT_TYPE);

        String body = String.format("{\"success\": false, \"message\": \"%s\"}", message);
        return response.writeWith(Mono.just(response.bufferFactory().wrap(body.getBytes())));
    }
}
