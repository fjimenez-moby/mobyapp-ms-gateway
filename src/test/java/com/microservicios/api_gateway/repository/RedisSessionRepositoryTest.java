package com.microservicios.api_gateway.repository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.ReactiveHashOperations;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RedisSessionRepositoryTest {

    @Mock
    private ReactiveRedisTemplate<String, String> redisTemplate;

    @Mock
    private ReactiveHashOperations<String, String, Object> hashOperations;

    private SessionRepository sessionRepository;

    @BeforeEach
    void setUp() {
        when(redisTemplate.opsForHash()).thenReturn(hashOperations);
        sessionRepository = new RedisSessionRepository(redisTemplate);
    }

    @Test
    void getAccessToken_existingToken_shouldReturnCleanToken() {
        String sessionId = "test-session-123";
        String redisKey = "spring:session:sessions:" + sessionId;
        String tokenWithQuotes = "\"ya29.tokenxxx\"";

        when(hashOperations.get(redisKey, "sessionAttr:accessToken"))
                .thenReturn(Mono.just(tokenWithQuotes));

        StepVerifier.create(sessionRepository.getAccessToken(sessionId))
                .expectNext("ya29.tokenxxx")
                .verifyComplete();

        verify(hashOperations).get(redisKey, "sessionAttr:accessToken");
    }

    @Test
    void getAccessToken_tokenWithoutQuotes_shouldReturnAsIs() {
        String sessionId = "test-session-123";
        String redisKey = "spring:session:sessions:" + sessionId;
        String tokenWithoutQuotes = "ya29.tokenxxx";

        when(hashOperations.get(redisKey, "sessionAttr:accessToken"))
                .thenReturn(Mono.just(tokenWithoutQuotes));

        StepVerifier.create(sessionRepository.getAccessToken(sessionId))
                .expectNext("ya29.tokenxxx")
                .verifyComplete();
    }

    @Test
    void getAccessToken_notFound_shouldReturnEmpty() {
        String sessionId = "non-existent-session";
        String redisKey = "spring:session:sessions:" + sessionId;

        when(hashOperations.get(redisKey, "sessionAttr:accessToken"))
                .thenReturn(Mono.empty());

        StepVerifier.create(sessionRepository.getAccessToken(sessionId))
                .verifyComplete();
    }

    @Test
    void getRefreshToken_existingToken_shouldReturnCleanToken() {
        String sessionId = "test-session-123";
        String redisKey = "spring:session:sessions:" + sessionId;
        String refreshToken = "\"1//refresh-token-xxx\"";

        when(hashOperations.get(redisKey, "sessionAttr:refreshToken"))
                .thenReturn(Mono.just(refreshToken));

        StepVerifier.create(sessionRepository.getRefreshToken(sessionId))
                .expectNext("1//refresh-token-xxx")
                .verifyComplete();
    }

    @Test
    void getRefreshToken_notFound_shouldReturnEmptyString() {
        String sessionId = "test-session-123";
        String redisKey = "spring:session:sessions:" + sessionId;

        when(hashOperations.get(redisKey, "sessionAttr:refreshToken"))
                .thenReturn(Mono.empty());

        StepVerifier.create(sessionRepository.getRefreshToken(sessionId))
                .expectNext("")
                .verifyComplete();
    }

    @Test
    void getAccessToken_redisError_shouldPropagateError() {
        String sessionId = "test-session-123";
        String redisKey = "spring:session:sessions:" + sessionId;

        when(hashOperations.get(redisKey, "sessionAttr:accessToken"))
                .thenReturn(Mono.error(new RuntimeException("Redis connection failed")));

        StepVerifier.create(sessionRepository.getAccessToken(sessionId))
                .expectErrorMessage("Redis connection failed")
                .verify();
    }
}
