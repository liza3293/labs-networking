package com.example.lab9.config;

import com.example.lab9.service.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class SessionValidatorInterceptor implements HandlerInterceptor {
    @Autowired
    private SessionService sessionService;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String sessionId = request.getHeader("x-session-id");
        if (sessionId == null || !sessionService.isValidSession(sessionId)) {
            response.setStatus(HttpStatus.PRECONDITION_FAILED.value());
            response.getWriter().write("Session expired or invalid");
            return false;
        }
        return true;
    }
}