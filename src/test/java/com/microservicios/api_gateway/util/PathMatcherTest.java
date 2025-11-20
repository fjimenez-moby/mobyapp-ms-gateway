package com.microservicios.api_gateway.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PathMatcherTest {

    @Test
    void matches_exactPath_shouldReturnTrue() {
        assertTrue(PathMatcher.matches("/api/auth/login", "/api/auth/login"));
    }

    @Test
    void matches_exactPath_shouldReturnFalse() {
        assertFalse(PathMatcher.matches("/api/auth/login", "/api/auth/logout"));
    }

    @Test
    void matches_wildcardPattern_shouldMatchPrefix() {
        assertTrue(PathMatcher.matches("/api/auth/login", "/api/auth/**"));
        assertTrue(PathMatcher.matches("/api/auth/logout", "/api/auth/**"));
        assertTrue(PathMatcher.matches("/api/auth/google/callback", "/api/auth/**"));
    }

    @Test
    void matches_wildcardPattern_shouldNotMatchDifferentPrefix() {
        assertFalse(PathMatcher.matches("/api/user/profile", "/api/auth/**"));
        assertFalse(PathMatcher.matches("/user/test", "/api/**"));
    }

    @Test
    void matches_nullPath_shouldReturnFalse() {
        assertFalse(PathMatcher.matches(null, "/api/**"));
    }

    @Test
    void matches_nullPattern_shouldReturnFalse() {
        assertFalse(PathMatcher.matches("/api/test", null));
    }

    @Test
    void matches_bothNull_shouldReturnFalse() {
        assertFalse(PathMatcher.matches(null, null));
    }

    @Test
    void matches_rootWildcard_shouldMatchAll() {
        assertTrue(PathMatcher.matches("/anything", "/**"));
        assertTrue(PathMatcher.matches("/api/test", "/**"));
    }
}
