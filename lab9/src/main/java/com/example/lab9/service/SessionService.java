package com.example.lab9.service;

import com.example.lab9.model.SessionData;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SessionService {
    private final ConcurrentHashMap<String, SessionData> sessions = new ConcurrentHashMap<>();
    @Value("${session.expiration.minutes:1}")  // Конфіг: 1 хв за замовчуванням
    private long expirationMinutes;

    public void createSession(String sessionId, SecretKey secretKey, byte[] iv) {
        LocalDateTime expiredAt = LocalDateTime.now(ZoneOffset.UTC).plusMinutes(expirationMinutes);
        sessions.put(sessionId, new SessionData(sessionId, secretKey, iv, expiredAt));
    }

    public SessionData getSession(String sessionId) {
        return sessions.get(sessionId);
    }

    public boolean isValidSession(String sessionId) {
        SessionData session = sessions.get(sessionId);
        if (session == null) return false;
        boolean valid = !LocalDateTime.now(ZoneOffset.UTC).isAfter(session.getExpiredAt());
        if (!valid) sessions.remove(sessionId);  // Видалити expired
        return valid;
    }

    public void invalidateSession(String sessionId) {
        sessions.remove(sessionId);
    }

    public boolean sessionExists(String sessionId) {
        return sessions.containsKey(sessionId);
    }

    // Task 3: Повертає всі сесії (копія для безпеки)
    public Map<String, SessionData> getAllSessions() {
        return new HashMap<>(sessions);
    }
}