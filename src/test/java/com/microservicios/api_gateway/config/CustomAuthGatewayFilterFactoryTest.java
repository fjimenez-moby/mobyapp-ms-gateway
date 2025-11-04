package com.microservicios.api_gateway.config;

import com.microservicios.api_gateway.repository.SessionRepository;
import com.microservicios.api_gateway.service.TokenValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.URI;
import java.util.Base64;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CustomAuthGatewayFilterFactoryTest {

    @Mock
    private SessionRepository sessionRepository;

    @Mock
    private TokenValidator tokenValidator;

    @Mock
    private ServerWebExchange exchange;

    @Mock
    private ServerHttpRequest request;

    @Mock
    private ServerHttpResponse response;

    @Mock
    private GatewayFilterChain chain;

    private CustomAuthGatewayFilterFactory filterFactory;

    @BeforeEach
    void setUp() {
        filterFactory = new CustomAuthGatewayFilterFactory(sessionRepository, tokenValidator);
    }

    @Test
    void apply_excludedPath_shouldBypassAuth() {
        // Given
        var config = new CustomAuthGatewayFilterFactory.Config(List.of("/api/auth/**"));
        GatewayFilter filter = filterFactory.apply(config);

        when(exchange.getRequest()).thenReturn(request);
        when(request.getURI()).thenReturn(URI.create("http://localhost/api/auth/login"));
        when(request.getPath()).thenReturn(mock(org.springframework.http.server.RequestPath.class));
        when(request.getPath().value()).thenReturn("/api/auth/login");
        when(chain.filter(exchange)).thenReturn(Mono.empty());

        // When
        Mono<Void> result = filter.filter(exchange, chain);

        // Then
        StepVerifier.create(result)
                .verifyComplete();

        verify(chain).filter(exchange);
        verifyNoInteractions(sessionRepository);
    }

    @Test
    void apply_noCookie_shouldReturnUnauthorized() {
        // Given
        var config = new CustomAuthGatewayFilterFactory.Config(null);
        GatewayFilter filter = filterFactory.apply(config);

        MultiValueMap<String, HttpCookie> cookies = new LinkedMultiValueMap<>();

        when(exchange.getRequest()).thenReturn(request);
        when(request.getURI()).thenReturn(URI.create("http://localhost/api/protected"));
        when(request.getPath()).thenReturn(mock(org.springframework.http.server.RequestPath.class));
        when(request.getPath().value()).thenReturn("/api/protected");
        when(request.getCookies()).thenReturn(cookies);
        when(exchange.getResponse()).thenReturn(response);

        // When
        Mono<Void> result = filter.filter(exchange, chain);

        // Then
        StepVerifier.create(result)
                .verifyComplete();

        verify(response).setStatusCode(HttpStatus.UNAUTHORIZED);
        verifyNoInteractions(sessionRepository);
    }

    @Test
    void apply_validTokenFlow_shouldInjectHeadersAndProceed() {
        // Given
        var config = new CustomAuthGatewayFilterFactory.Config(null);
        GatewayFilter filter = filterFactory.apply(config);

        String rawSessionId = "session-123";
        String encodedSessionId = Base64.getEncoder().encodeToString(rawSessionId.getBytes());
        String accessToken = "ya29.validtoken";
        String refreshToken = "refresh-token";

        HttpCookie sessionCookie = new HttpCookie("JSESSIONID", encodedSessionId);
        MultiValueMap<String, HttpCookie> cookies = new LinkedMultiValueMap<>();
        cookies.add("JSESSIONID", sessionCookie);

        when(exchange.getRequest()).thenReturn(request);
        when(request.getURI()).thenReturn(URI.create("http://localhost/api/protected"));
        when(request.getPath()).thenReturn(mock(org.springframework.http.server.RequestPath.class));
        when(request.getPath().value()).thenReturn("/api/protected");
        when(request.getCookies()).thenReturn(cookies);

        when(sessionRepository.getAccessToken(rawSessionId))
                .thenReturn(Mono.just(accessToken));
        when(sessionRepository.getRefreshToken(rawSessionId))
                .thenReturn(Mono.just(refreshToken));
        when(tokenValidator.isValid(accessToken)).thenReturn(true);

        when(exchange.mutate()).thenReturn(mock(ServerWebExchange.Builder.class));
        when(chain.filter(any())).thenReturn(Mono.empty());

        // When
        Mono<Void> result = filter.filter(exchange, chain);

        // Then
        StepVerifier.create(result)
                .verifyComplete();

        verify(sessionRepository).getAccessToken(rawSessionId);
        verify(tokenValidator).isValid(accessToken);
    }
}
