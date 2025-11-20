package com.microservicios.api_gateway.util;

public final class JsonStringCleaner {

    private JsonStringCleaner() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    public static String removeQuotes(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }

        if (value.startsWith("\"") && value.endsWith("\"") && value.length() >= 2) {
            return value.substring(1, value.length() - 1);
        }

        return value;
    }
}
