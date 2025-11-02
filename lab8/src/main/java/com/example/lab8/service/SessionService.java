package com.example.lab8.service;

import com.example.lab8.model.SessionData;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SessionService {
    private final ConcurrentHashMap<String, SessionData> sessions = new ConcurrentHashMap<>();

    public void createSession(String sessionId, SecretKey secretKey, byte[] iv) {
        sessions.put(sessionId, new SessionData(sessionId, secretKey, iv));
    }

    public SessionData getSession(String sessionId) {
        return sessions.get(sessionId);
    }

    public boolean sessionExists(String sessionId) {
        return sessions.containsKey(sessionId);
    }
}