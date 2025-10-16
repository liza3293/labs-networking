package com.example.lab6;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@OpenAPIDefinition(info = @Info(title = "TestServer.Api", version = "1.0"))
public class Lab6Application {
	public static void main(String[] args) {
		SpringApplication.run(Lab6Application.class, args);
	}
}