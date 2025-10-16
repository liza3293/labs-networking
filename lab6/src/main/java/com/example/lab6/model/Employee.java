package com.example.lab6.model;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import io.swagger.v3.oas.annotations.media.Schema;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Модель працівника")
public class Employee {
    @Schema(description = "Унікальний ідентифікатор працівника", example = "1")
    private Integer id;

    @Schema(description = "Ім'я працівника", example = "Іван")
    private String firstName;

    @Schema(description = "Прізвище працівника", example = "Петренко")
    private String lastName;

    @Schema(description = "Вік працівника", example = "30")
    private Integer age;
}