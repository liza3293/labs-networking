package com.example.lab7.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.Contact;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Employee Management API")
                        .version("1.0")
                        .description("REST API для управління працівниками")
                        .contact(new Contact()
                                .name("Білоус Єлизавета")
                                .email("yelyzaveta.bilous@student.karazin.ua")));
    }
}