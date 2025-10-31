package com.example.lab7;

import com.example.lab7.model.AesKey;
import com.example.lab7.service.AesService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class AesServiceTest {

    @Autowired
    private AesService aesService;

    @Test
    void testGenerateKey() {
        AesKey key = aesService.generateKey();
        assertNotNull(key.getKey());
        assertNotNull(key.getIv());
    }

    @Test
    void testEncryptAndDecrypt() {
        // Arrange
        AesKey key = aesService.generateKey();
        String originalText = "Hello, AES!";

        // Act
        String encrypted = aesService.encrypt(key, originalText);
        String decrypted = aesService.decrypt(key, encrypted);

        // Assert
        assertNotNull(encrypted);
        assertEquals(originalText, decrypted);
    }
}