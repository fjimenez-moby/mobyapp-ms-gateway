package com.microservicios.api_gateway.util;

public final class PathMatcher {

    private PathMatcher() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    /**
     * Verifies if a request path matches a given pattern.
     * Supports wildcard patterns ending with /**
     *
     * @param requestPath the path to check
     * @param pattern the pattern to match against (supports /** wildcard)
     * @return true if the path matches the pattern
     */
    public static boolean matches(String requestPath, String pattern) {
        if (requestPath == null || pattern == null) {
            return false;
        }

        // Si el patrón termina con /**, verificar si el path empieza con la base
        if (pattern.endsWith("/**")) {
            String basePath = pattern.substring(0, pattern.length() - 3);
            return requestPath.startsWith(basePath);
        }

        // Coincidencia exacta
        return requestPath.equals(pattern);
    }
}
