package com.example.lab7.controller;

import com.example.lab7.model.AesKey;
import com.example.lab7.model.RsaKeys;
import com.example.lab7.service.AesService;
import com.example.lab7.service.RsaService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

@RestController
@RequestMapping("/api/crypto-keys")
public class CryptoController {

    private final RsaService rsaService;
    private final AesService aesService;
    private final Map<Integer, RsaKeys> rsaKeysMap = new HashMap<>();
    private final AtomicInteger idCounter = new AtomicInteger(1);

    public CryptoController(RsaService rsaService, AesService aesService) {
        this.rsaService = rsaService;
        this.aesService = aesService;
    }

    @PostMapping("/generate/rsa-keys")
    public ResponseEntity<?> generateRsaKeys() {
        try {
            RsaKeys keys = rsaService.generateKeyPair();
            int id = idCounter.getAndIncrement();
            rsaKeysMap.put(id, keys);
            return ResponseEntity.ok(id);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Помилка генерації ключів: " + e.getMessage());
        }
    }

    @GetMapping("/rsa-public-key/{id}")
    public ResponseEntity<?> getRsaPublicKey(@PathVariable Integer id) {
        RsaKeys keys = rsaKeysMap.get(id);
        if (keys == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(keys.getPublicKey());
    }

    // Додатковий метод для отримання приватного ключа (для тестування)
    @GetMapping("/rsa-private-key/{id}")
    public ResponseEntity<?> getRsaPrivateKey(@PathVariable Integer id) {
        RsaKeys keyPair = rsaKeysMap.get(id);
        if (keyPair == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(keyPair.getPrivateKey());
    }

    // RSA
    @PostMapping("/rsa/encrypt")
    public ResponseEntity<?> rsaEncrypt(@RequestParam String publicKey,
                                        @RequestParam String text) {
        try {
            String encrypted = rsaService.encrypt(publicKey, text);
            return ResponseEntity.ok(encrypted);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Помилка шифрування: " + e.getMessage());
        }
    }

    @PostMapping("/rsa/decrypt")
    public ResponseEntity<?> rsaDecrypt(@RequestParam String privateKey,
                                        @RequestParam String cipherText) {
        try {
            String decrypted = rsaService.decrypt(privateKey, cipherText);
            return ResponseEntity.ok(decrypted);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Помилка дешифрування: " + e.getMessage());
        }
    }

    // AES
    @PostMapping("/aes/generate-key")
    public ResponseEntity<AesKey> generateAesKey() {
        AesKey aesKey = aesService.generateKey();
        return ResponseEntity.ok(aesKey);
    }

    @PostMapping("/aes/encrypt")
    public ResponseEntity<?> aesEncrypt(@RequestBody AesKey aesKey,
                                        @RequestParam String text) {
        try {
            String encrypted = aesService.encrypt(aesKey, text);
            return ResponseEntity.ok(encrypted);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Помилка шифрування: " + e.getMessage());
        }
    }

    @PostMapping("/aes/decrypt")
    public ResponseEntity<?> aesDecrypt(@RequestBody AesKey aesKey,
                                        @RequestParam String cipherText) {
        try {
            String decrypted = aesService.decrypt(aesKey, cipherText);
            return ResponseEntity.ok(decrypted);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Помилка дешифрування: " + e.getMessage());
        }
    }
}