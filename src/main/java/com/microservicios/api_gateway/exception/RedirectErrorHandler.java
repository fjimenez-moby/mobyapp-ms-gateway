package com.microservicios.api_gateway.exception;

import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

@Component
@Order(-2) // más prioritario que el handler por defecto
public class RedirectErrorHandler implements ErrorWebExceptionHandler {

    private static final URI TARGET = URI.create("http://localhost:9000");

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
        ServerHttpResponse resp = exchange.getResponse();
        if (resp.isCommitted()) return Mono.error(ex);

        // Opcional: filtrar por tipos de excepción si querés sólo ciertos casos.
        resp.setStatusCode(HttpStatus.FOUND); // 302
        resp.getHeaders().setLocation(TARGET);
        resp.getHeaders().remove("Content-Length");
        return resp.setComplete();
    }
}