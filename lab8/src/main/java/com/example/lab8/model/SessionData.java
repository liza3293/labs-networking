package com.example.lab8.model;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;

public class SessionData {
    private String sessionId;
    private SecretKey secretKey;
    private byte[] iv;
    private LocalDateTime created;

    public SessionData(String sessionId, SecretKey secretKey, byte[] iv) {
        this.sessionId = sessionId;
        this.secretKey = secretKey;
        this.iv = iv;
        this.created = LocalDateTime.now();
    }

    public String getSessionId() { return sessionId; }
    public void setSessionId(String sessionId) { this.sessionId = sessionId; }

    public SecretKey getSecretKey() { return secretKey; }
    public void setSecretKey(SecretKey secretKey) { this.secretKey = secretKey; }

    public byte[] getIv() { return iv; }
    public void setIv(byte[] iv) { this.iv = iv; }

    public LocalDateTime getCreated() { return created; }
    public void setCreated(LocalDateTime created) { this.created = created; }
}