package com.example.lab9.controller;

import com.example.lab9.model.AesKey;
import com.example.lab9.model.RsaKeys;
import com.example.lab9.model.SessionData;
import com.example.lab9.service.AesService;
import com.example.lab9.service.RsaService;
import com.example.lab9.service.SessionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@RestController
@RequestMapping("/api/secure")
public class SecureCommunicationController {

    private final RsaService rsaService;
    private final AesService aesService;
    private final SessionService sessionService;
    private final Map<Integer, RsaKeys> rsaKeysMap = new ConcurrentHashMap<>();
    private final AtomicInteger keyCounter = new AtomicInteger(1);

    @Autowired
    public SecureCommunicationController(RsaService rsaService, AesService aesService, SessionService sessionService) {
        this.rsaService = rsaService;
        this.aesService = aesService;
        this.sessionService = sessionService;
        initializeKeyPairs();
    }

    private void initializeKeyPairs() {
        // Генерація 10 пар RSA ключів при старті
        for (int i = 0; i < 10; i++) {
            RsaKeys keys = rsaService.generateKeyPair();
            rsaKeysMap.put(keyCounter.getAndIncrement(), keys);
        }
    }

    // Ендпоінт для отримання випадкового публічного ключа
    @GetMapping("/public-key")
    public ResponseEntity<Map<String, Object>> getRandomPublicKey() {
        try {
            // Вибираємо випадковий ключ
            int randomIndex = (int) (Math.random() * rsaKeysMap.size()) + 1;
            RsaKeys randomKeys = rsaKeysMap.get(randomIndex);

            Map<String, Object> response = new HashMap<>();
            response.put("keyId", randomIndex);
            response.put("publicKey", randomKeys.getPublicKey());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // Ендпоінт для отримання конкретного публічного ключа за ID
    @GetMapping("/public-key/{keyId}")
    public ResponseEntity<?> getPublicKeyById(@PathVariable Integer keyId) {
        RsaKeys keys = rsaKeysMap.get(keyId);
        if (keys == null) {
            return ResponseEntity.notFound().build();
        }

        Map<String, Object> response = new HashMap<>();
        response.put("keyId", keyId);
        response.put("publicKey", keys.getPublicKey());

        return ResponseEntity.ok(response);
    }

    // Task 3: Ендпоінт для отримання інформації про всі сесії (активні + невалідні)
    @GetMapping("/sessions")
    public ResponseEntity<List<Map<String, Object>>> getAllSessions() {
        try {
            List<Map<String, Object>> sessionsList = new ArrayList<>();
            for (Map.Entry<String, SessionData> entry : sessionService.getAllSessions().entrySet()) {
                String sessionId = entry.getKey();
                SessionData sd = entry.getValue();
                Map<String, Object> info = new HashMap<>();
                info.put("id", sessionId);
                info.put("status", sessionService.isValidSession(sessionId) ? "valid" : "invalid");  // Стан: валідна/не валідна
                info.put("expiredAt", sd.getExpiredAt().toString());  // Термін дії (ISO UTC)
                sessionsList.add(info);
            }
            return ResponseEntity.ok(sessionsList);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ArrayList<>());
        }
    }

    // Ендпоінт для налаштування сесії
    @PostMapping("/setup-session")
    public ResponseEntity<?> setupSession(@RequestHeader("x-rsa-id") Integer keyId,
                                          @RequestBody Map<String, String> request) {
        try {
            String encryptedSessionData = request.get("encryptedData");

            RsaKeys keys = rsaKeysMap.get(keyId);
            if (keys == null) {
                return ResponseEntity.badRequest().body("Invalid key ID");
            }

            // Дешифруємо дані сесії приватним ключем
            String decryptedData = rsaService.decrypt(keys.getPrivateKey(), encryptedSessionData);

            // Парсимо дані сесії: sessionId|secretKeyBase64|ivBase64
            String[] sessionDataParts = decryptedData.split("\\|");
            if (sessionDataParts.length != 3) {
                return ResponseEntity.badRequest().body("Invalid session data format");
            }

            String sessionId = sessionDataParts[0];
            String secretKeyBase64 = sessionDataParts[1];
            String ivBase64 = sessionDataParts[2];

            // Конвертуємо назад в SecretKey
            byte[] keyBytes = Base64.getDecoder().decode(secretKeyBase64);
            javax.crypto.SecretKey secretKey = new javax.crypto.spec.SecretKeySpec(keyBytes, "AES");
            byte[] iv = Base64.getDecoder().decode(ivBase64);

            // Зберігаємо сесію з expiration (SessionService автоматично додає expiredAt)
            sessionService.createSession(sessionId, secretKey, iv);

            Map<String, String> response = new HashMap<>();
            response.put("sessionId", sessionId);
            response.put("status", "Session established successfully");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to setup session: " + e.getMessage());
        }
    }

    // Ендпоінт для обміну повідомленнями
    @PostMapping("/message")
    public ResponseEntity<?> handleMessage(@RequestHeader("x-session-id") String sessionId,
                                           @RequestHeader(value = "x-hash", required = false) String receivedHash,  // Task 2: Хеш з заголовка
                                           @RequestBody Map<String, String> request) {
        try {
            // Task 1: Перевірка валідності сесії
            if (!sessionService.isValidSession(sessionId)) {
                sessionService.invalidateSession(sessionId);  // Помітити як не валідну
                return ResponseEntity.status(440).body("Session expired");  // Код 440
            }

            // Task 2: Перевірка хешу (якщо немає — помилка)
            if (receivedHash == null) {
                return ResponseEntity.badRequest().body("Missing integrity hash (x-hash)");
            }

            SessionData session = sessionService.getSession(sessionId);
            if (session == null) {
                return ResponseEntity.badRequest().body("Invalid session ID");
            }

            String encryptedMessage = request.get("encryptedMessage");

            // Створюємо AesKey для використання в сервісі
            AesKey aesKey = new AesKey(
                    Base64.getEncoder().encodeToString(session.getSecretKey().getEncoded()),
                    Base64.getEncoder().encodeToString(session.getIv())
            );

            // Дешифруємо повідомлення
            String decryptedMessage = aesService.decrypt(aesKey, encryptedMessage);

            // Task 2: Перевірка цілісності — обчислюємо хеш decryptedMessage і порівнюємо
            String computedHash = computeHash(decryptedMessage);
            if (!receivedHash.equals(computedHash)) {
                return ResponseEntity.status(400).body("Integrity check failed: Hash mismatch");
            }
            System.out.println("Integrity check passed: Hash matches");  // Дебаг лог

            // Додаємо інформацію про час отримання (UTC)
            String processedMessage = decryptedMessage + " | Received: " + LocalDateTime.now(ZoneOffset.UTC);

            // Шифруємо відповідь
            String encryptedResponse = aesService.encrypt(aesKey, processedMessage);

            Map<String, Object> response = new HashMap<>();
            response.put("encryptedResponse", encryptedResponse);
            response.put("sessionId", sessionId);
            response.put("processedAt", LocalDateTime.now(ZoneOffset.UTC).toString());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to process message: " + e.getMessage());
        }
    }

    // Task 2: Обчислення SHA-256 хешу (аналогічно клієнту)
    private String computeHash(String data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hashBytes);
    }
}