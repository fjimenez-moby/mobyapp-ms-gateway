package com.microservicios.api_gateway.config;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

@Component
public class FallbackRoutes implements GlobalFilter, Ordered {

        private static final URI TARGET = URI.create("http://localhost:9000");

        @Override
        public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
            // 1) Si ocurre excepción en la cadena, redirigir
            return chain.filter(exchange)
                    .onErrorResume(ex -> {
                        var resp = exchange.getResponse();
                        if (!resp.isCommitted()) {
                            resp.setStatusCode(HttpStatus.FOUND);
                            resp.getHeaders().setLocation(TARGET);
                            resp.getHeaders().remove("Content-Length");
                            return resp.setComplete();
                        }
                        return Mono.error(ex);
                    })
                    // 2) Si la respuesta llegó y es 5xx, redirigir igual
                    .then(Mono.defer(() -> {
                        ServerHttpResponse resp = exchange.getResponse();
                        var sc = resp.getStatusCode();
                        if (!resp.isCommitted() && sc != null && sc.is5xxServerError()) {
                            resp.setStatusCode(HttpStatus.FOUND);
                            resp.getHeaders().setLocation(TARGET);
                            resp.getHeaders().remove("Content-Length");
                            return resp.setComplete();
                        }
                        return Mono.empty();
                    }));
        }

        @Override
        public int getOrder() {
            // Debe correr antes del NettyWriteResponseFilter (-1)
            return -2;
        }
    }