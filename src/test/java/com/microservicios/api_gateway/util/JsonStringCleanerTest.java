package com.microservicios.api_gateway.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JsonStringCleanerTest {

    @Test
    void removeQuotes_withQuotes_shouldRemoveThem() {
        assertEquals("token123", JsonStringCleaner.removeQuotes("\"token123\""));
    }

    @Test
    void removeQuotes_withoutQuotes_shouldReturnSame() {
        assertEquals("token123", JsonStringCleaner.removeQuotes("token123"));
    }

    @Test
    void removeQuotes_onlyStartQuote_shouldReturnSame() {
        assertEquals("\"token123", JsonStringCleaner.removeQuotes("\"token123"));
    }

    @Test
    void removeQuotes_onlyEndQuote_shouldReturnSame() {
        assertEquals("token123\"", JsonStringCleaner.removeQuotes("token123\""));
    }

    @Test
    void removeQuotes_emptyString_shouldReturnEmpty() {
        assertEquals("", JsonStringCleaner.removeQuotes(""));
    }

    @Test
    void removeQuotes_onlyQuotes_shouldReturnEmpty() {
        assertEquals("", JsonStringCleaner.removeQuotes("\"\""));
    }

    @Test
    void removeQuotes_null_shouldReturnNull() {
        assertNull(JsonStringCleaner.removeQuotes(null));
    }

    @Test
    void removeQuotes_quotesInMiddle_shouldNotRemove() {
        assertEquals("token\"123", JsonStringCleaner.removeQuotes("token\"123"));
    }
}
