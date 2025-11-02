package com.example.lab8.client;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SecureClient {
    private static final String BASE_URL = "http://localhost:8081/api/secure";
    private static final HttpClient httpClient = HttpClient.newHttpClient();
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private String currentSessionId;
    private SecretKey currentSecretKey;
    private byte[] currentIV;

    public static void main(String[] args) {
        SecureClient client = new SecureClient();
        client.start();
    }

    public void start() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== Secure Communication Client ===");

        while (true) {
            System.out.print("\nEnter your message (or 'quit' to exit): ");
            String userMessage = scanner.nextLine();

            if ("quit".equalsIgnoreCase(userMessage)) {
                break;
            }

            try {
                processMessage(userMessage);
            } catch (Exception e) {
                System.err.println("Error processing message: " + e.getMessage());
                e.printStackTrace();
            }
        }

        scanner.close();
        System.out.println("Client stopped.");
    }

    private void processMessage(String userMessage) throws Exception {
        System.out.println("\n=== Starting Secure Communication ===");

        // Крок a: [Клієнт] Отримати публічний ключ з серверу
        System.out.println("1. Getting public key from server...");
        HttpRequest publicKeyRequest = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/public-key"))
                .GET()
                .build();

        HttpResponse<String> publicKeyResponse = httpClient.send(publicKeyRequest, HttpResponse.BodyHandlers.ofString());
        if (publicKeyResponse.statusCode() != 200) {
            throw new RuntimeException("Failed to get public key: " + publicKeyResponse.body());
        }
        System.out.println("   Response status: " + publicKeyResponse.statusCode());
        @SuppressWarnings("unchecked")
        Map<String, Object> publicKeyData = objectMapper.readValue(publicKeyResponse.body(), HashMap.class);

        int keyId = (Integer) publicKeyData.get("keyId");
        String publicKeyBase64 = (String) publicKeyData.get("publicKey");

        System.out.println("   Received Key ID: " + keyId);

        // Крок b: [Клієнт] Створити таємний ключ та масив ініціалізації для симетричного шифрування
        System.out.println("2. Generating session key and IV...");
        currentSecretKey = generateAESKey();
        currentIV = generateIV();
        currentSessionId = "client_session_" + System.currentTimeMillis();

        // Крок c: [Клієнт] Створити номер сесії, до якої буде належати таємний ключ

        // Крок d: [Клієнт] Зашифрувати публічним ключем інформацію необхідну для створення каналу симетричного шифрування
        System.out.println("3. Encrypting session data with public key...");
        String sessionData = currentSessionId + "|" + Base64.getEncoder().encodeToString(currentSecretKey.getEncoded()) + "|" + Base64.getEncoder().encodeToString(currentIV);
        String encryptedSessionData = encryptRSA(publicKeyBase64, sessionData);

        // Крок d: та відправити на сервер
        System.out.println("4. Sending encrypted session data to server...");

        Map<String, String> sessionRequest = new HashMap<>();
        sessionRequest.put("encryptedData", encryptedSessionData);

        HttpRequest setupSessionRequest = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/setup-session"))
                .header("Content-Type", "application/json")
                .header("x-rsa-id", String.valueOf(keyId))
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(sessionRequest)))
                .build();

        HttpResponse<String> sessionResponse = httpClient.send(setupSessionRequest, HttpResponse.BodyHandlers.ofString());
        if (sessionResponse.statusCode() != 200) {
            throw new RuntimeException("Failed to setup session: " + sessionResponse.body());
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> sessionResponseData = objectMapper.readValue(sessionResponse.body(), HashMap.class);

        System.out.println("   Session setup: " + sessionResponseData.get("status"));

        // Крок f: [Клієнт] Шифрування повідомлення юзера за допомогою симетричного алгоритму, відправка до серверу
        System.out.println("5. Encrypting user message...");
        String encryptedMessage = encryptAES(userMessage);

        System.out.println("6. Sending encrypted message to server...");

        Map<String, String> messageRequest = new HashMap<>();
        messageRequest.put("encryptedMessage", encryptedMessage);

        HttpRequest sendMessageRequest = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/message"))
                .header("Content-Type", "application/json")
                .header("x-session-id", currentSessionId)
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(messageRequest)))
                .build();

        HttpResponse<String> messageResponse = httpClient.send(sendMessageRequest, HttpResponse.BodyHandlers.ofString());
        if (messageResponse.statusCode() != 200) {
            throw new RuntimeException("Failed to send message: " + messageResponse.body());
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> messageResponseData = objectMapper.readValue(messageResponse.body(), HashMap.class);

        // Крок h: [Клієнт] Дешифрування повідомлення, вивод отриманого повідомлення на екран, а також інформації про номер сесії.
        System.out.println("7. Decrypting server response...");
        String encryptedResponse = (String) messageResponseData.get("encryptedResponse");
        String decryptedResponse = decryptAES(encryptedResponse);

        // Вивід результатів
        System.out.println("\n=== COMMUNICATION RESULTS ===");
        System.out.println("Session ID: " + currentSessionId);
        System.out.println("Original message: " + userMessage);
        System.out.println("Server response: " + decryptedResponse);
        System.out.println("Processed at: " + messageResponseData.get("processedAt"));
        System.out.println("==============================");
    }

    private SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    private byte[] generateIV() {
        byte[] iv = new byte[16];
        new java.security.SecureRandom().nextBytes(iv);
        return iv;
    }

    private String encryptRSA(String publicKeyBase64, String data) throws Exception {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private String encryptAES(String data) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(currentSecretKey.getEncoded(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(currentIV);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private String decryptAES(String encryptedData) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(currentSecretKey.getEncoded(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(currentIV);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes, "UTF-8");
    }
}