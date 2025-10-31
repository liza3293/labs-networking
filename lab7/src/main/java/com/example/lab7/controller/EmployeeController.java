package com.example.lab7.controller;

import com.example.lab7.model.Employee;
import com.example.lab7.service.EmployeeService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/employees")
@Tag(name = "Employees API", description = "API для управління працівниками")
public class EmployeeController {

    private final EmployeeService employeeService;

    public EmployeeController(EmployeeService employeeService) {
        this.employeeService = employeeService;
    }

    @GetMapping
    @Operation(summary = "Отримати всіх працівників", description = "Повертає список усіх працівників")
    @ApiResponse(responseCode = "200", description = "Успішно отримано список працівників")
    public List<Employee> getAllEmployees() {
        return employeeService.getAllEmployees();
    }

    @GetMapping("/{id}")
    @Operation(summary = "Отримати працівника по ID", description = "Повертає працівника за вказаним ідентифікатором")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Працівник знайдений"),
            @ApiResponse(responseCode = "404", description = "Працівник не знайдений")
    })
    public ResponseEntity<Employee> getEmployeeById(
            @Parameter(description = "ID працівника", example = "1")
            @PathVariable Integer id) {
        Employee employee = employeeService.getEmployeeById(id);
        return employee != null ? ResponseEntity.ok(employee) : ResponseEntity.notFound().build();
    }

    @PostMapping
    @Operation(summary = "Створити нового працівника", description = "Створює нового працівника в системі")
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Працівник успішно створений"),
            @ApiResponse(responseCode = "400", description = "Невірні дані або працівник вже існує")
    })
    public ResponseEntity<?> createEmployee(
            @Parameter(description = "Дані нового працівника")
            @RequestBody Employee employee) {
        if (employeeService.employeeExists(employee.getFirstName(), employee.getLastName(), employee.getAge())) {
            return ResponseEntity.badRequest().body("Працівник з таким ім'ям, прізвищем та віком вже існує");
        }
        Employee created = employeeService.createEmployee(employee);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @PutMapping("/{id}")
    @Operation(summary = "Оновити дані працівника", description = "Оновлює інформацію про існуючого працівника")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Дані працівника успішно оновлені"),
            @ApiResponse(responseCode = "404", description = "Працівник не знайдений")
    })
    public ResponseEntity<?> updateEmployee(  // Змінили на <?>
                                              @Parameter(description = "ID працівника для оновлення", example = "1")
                                              @PathVariable Integer id,
                                              @Parameter(description = "Нові дані працівника")
                                              @RequestBody Employee employeeDetails) {
        Employee updated = employeeService.updateEmployee(id, employeeDetails);
        if (updated != null) {
            return ResponseEntity.ok(updated);
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body("Працівник з ID " + id + " не знайдений");
        }
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Видалити працівника", description = "Видаляє працівника з системи за вказаним ID")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Працівник успішно видалений"),
            @ApiResponse(responseCode = "404", description = "Працівник не знайдений")
    })
    public ResponseEntity<?> deleteEmployee(
            @Parameter(description = "ID працівника для видалення", example = "1")
            @PathVariable Integer id) {
        boolean deleted = employeeService.deleteEmployee(id);
        return deleted ? ResponseEntity.ok("Працівник успішно видалений") : ResponseEntity.notFound().build();
    }
}