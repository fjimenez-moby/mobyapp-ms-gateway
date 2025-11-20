package com.microservicios.api_gateway.repository;

import com.microservicios.api_gateway.constants.AuthenticationConstants;
import com.microservicios.api_gateway.util.JsonStringCleaner;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public class RedisSessionRepository implements SessionRepository {

    private final ReactiveRedisTemplate<String, String> redisTemplate;

    public RedisSessionRepository(ReactiveRedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public Mono<String> getAccessToken(String sessionId) {
        String springSessionKey = buildSessionKey(sessionId);
        return redisTemplate.opsForHash()
                .get(springSessionKey, AuthenticationConstants.SESSION_ATTR_ACCESS_TOKEN)
                .map(Object::toString)
                .map(JsonStringCleaner::removeQuotes);
    }

    @Override
    public Mono<String> getRefreshToken(String sessionId) {
        String springSessionKey = buildSessionKey(sessionId);
        return redisTemplate.opsForHash()
                .get(springSessionKey, AuthenticationConstants.SESSION_ATTR_REFRESH_TOKEN)
                .map(Object::toString)
                .map(JsonStringCleaner::removeQuotes)
                .defaultIfEmpty("");
    }

    private String buildSessionKey(String sessionId) {
        return AuthenticationConstants.SPRING_SESSION_KEY_PREFIX + sessionId;
    }
}
