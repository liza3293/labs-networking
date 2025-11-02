package com.example.lab8;

import com.example.lab8.model.RsaKeys;
import com.example.lab8.service.RsaService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class RsaServiceTest {

    @Autowired
    private RsaService rsaService;

    @Test
    void testGenerateKeyPair() {
        RsaKeys keys = rsaService.generateKeyPair();
        assertNotNull(keys.getPublicKey());
        assertNotNull(keys.getPrivateKey());
    }

    @Test
    void testEncryptAndDecrypt() {
        // Arrange
        RsaKeys keys = rsaService.generateKeyPair();
        String originalText = "Hello, RSA!";

        // Act
        String encrypted = rsaService.encrypt(keys.getPublicKey(), originalText);
        String decrypted = rsaService.decrypt(keys.getPrivateKey(), encrypted);

        // Assert
        assertNotNull(encrypted);
        assertEquals(originalText, decrypted);
    }
}