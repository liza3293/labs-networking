package com.example.lab8;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Lab8Application {
	public static void main(String[] args) {
		SpringApplication.run(Lab8Application.class, args);
		System.out.println("Secure Communication Server is running on port 8080");
		System.out.println("Available endpoints:");
		System.out.println("  GET  /api/secure/public-key");
		System.out.println("  POST /api/secure/setup-session");
		System.out.println("  POST /api/secure/message");
		System.out.println("  GET  /api/crypto-keys/* (from previous lab)");
	}
}