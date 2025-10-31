package com.example.lab7.service;

import com.example.lab7.model.Employee;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class EmployeeService {
    private final List<Employee> employees = new ArrayList<>();
    private final AtomicInteger idCounter = new AtomicInteger(0);

    public List<Employee> getAllEmployees() {
        return new ArrayList<>(employees);
    }

    public Employee getEmployeeById(Integer id) {
        return employees.stream()
                .filter(emp -> emp.getId().equals(id))
                .findFirst()
                .orElse(null);
    }

    public Employee createEmployee(Employee employee) {
        employee.setId(idCounter.incrementAndGet());
        employees.add(employee);
        return employee;
    }

    public Employee updateEmployee(Integer id, Employee employeeDetails) {
        Employee employee = getEmployeeById(id);
        if (employee != null) {
            employee.setFirstName(employeeDetails.getFirstName());
            employee.setLastName(employeeDetails.getLastName());
            employee.setAge(employeeDetails.getAge());
        }
        return employee;
    }

    public boolean deleteEmployee(Integer id) {
        return employees.removeIf(emp -> emp.getId().equals(id));
    }

    public boolean employeeExists(String firstName, String lastName, Integer age) {
        return employees.stream()
                .anyMatch(emp -> emp.getFirstName().equals(firstName)
                        && emp.getLastName().equals(lastName)
                        && emp.getAge().equals(age));
    }
}