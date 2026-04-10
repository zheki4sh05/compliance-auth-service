package com.trustflow.compliance_auth_service.controller;

import com.trustflow.compliance_auth_service.dto.UserDto;
import com.trustflow.compliance_auth_service.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Tag(name = "User Management", description = "Endpoints для управления пользователями")
@SecurityRequirement(name = "Bearer Authentication")
public class UserController {

    private final UserService userService;

    @Operation(summary = "Получить всех пользователей")
    @PreAuthorize("hasRole('EXECUTIVE')")
    @GetMapping
    public ResponseEntity<List<UserDto>> getAllUsers() {
        return ResponseEntity.ok(userService.findAll());
    }

    @Operation(summary = "Получить пользователя по ID")
    @GetMapping("/{id}")
    public ResponseEntity<UserDto> getUserById(@PathVariable UUID id) {
        return ResponseEntity.ok(userService.findById(id));
    }

    @Operation(summary = "Создать нового пользователя")
    @PreAuthorize("hasRole('EXECUTIVE')")
    @PostMapping
    public ResponseEntity<UserDto> createUser(@RequestBody UserDto userDto) {
        UserDto created = userService.create(userDto);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @Operation(summary = "Обновить пользователя")
    @PutMapping("/{id}")
    public ResponseEntity<UserDto> updateUser(@PathVariable UUID id, @RequestBody UserDto userDto) {
        UserDto updated = userService.update(id, userDto);
        return ResponseEntity.ok(updated);
    }

    @Operation(summary = "Удалить пользователя")
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable UUID id) {
        userService.delete(id);
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Получить текущего пользователя")
    @GetMapping("/me")
    public ResponseEntity<UserDto> getCurrentUser() {
        return ResponseEntity.ok(userService.getCurrentUser());
    }
}
