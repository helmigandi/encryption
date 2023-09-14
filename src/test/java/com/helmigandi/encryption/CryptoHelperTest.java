package com.helmigandi.encryption;

import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class CryptoHelperTest {

    @Test
    void itShouldGenerateKey() throws NoSuchAlgorithmException {
        // Given
        String key = CryptoHelper.generateKey();
        // Then
        System.out.println("AES Key : "+key);
    }
}