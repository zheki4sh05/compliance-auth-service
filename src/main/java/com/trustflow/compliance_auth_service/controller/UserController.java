package com.trustflow.compliance_auth_service.controller;

import com.trustflow.compliance_auth_service.dto.AdminLoginUserDto;
import com.trustflow.compliance_auth_service.dto.CompanyUsersResponseDto;
import com.trustflow.compliance_auth_service.dto.UserDto;
import com.trustflow.compliance_auth_service.dto.UserStatusDto;
import com.trustflow.compliance_auth_service.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Tag(name = "User Management", description = "Endpoints для управления пользователями")
@SecurityRequirement(name = "Bearer Authentication")
public class UserController {

    private final UserService userService;

    @Operation(summary = "Получить всех пользователей")
    @GetMapping
    public ResponseEntity<CompanyUsersResponseDto> getAllUsers(@RequestHeader("companyId") String companyId) {
        return ResponseEntity.ok(userService.findAllByCompanyId(companyId));
    }

    @Operation(summary = "Получить пользователя по ID")
    @GetMapping("/{id}")
    public ResponseEntity<UserDto> getUserById(@PathVariable UUID id) {
        return ResponseEntity.ok(userService.findById(id));
    }

    @Operation(summary = "Создать нового пользователя")
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

    @Operation(summary = "Изменить статус пользователя (active/blocked)")
    @PutMapping("/{id}/status")
    public ResponseEntity<?> updateUserStatus(
            @PathVariable UUID id,
            @RequestHeader("companyId") String companyId,
            @RequestBody UserStatusDto userStatusDto) {
        try {
            UserStatusDto updatedStatus = userService.updateUserStatus(id, companyId, userStatusDto);
            return ResponseEntity.ok(updatedStatus);
        } catch (AuthenticationCredentialsNotFoundException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("message", "Требуется вход"));
        } catch (AccessDeniedException ex) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("message", "Недостаточно прав"));
        } catch (UsernameNotFoundException ex) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("message", "Пользователь не найден"));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(Map.of("message", "Некорректный статус"));
        }
    }

    @Operation(summary = "Удалить пользователя")
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable UUID id) {
        userService.delete(id);
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Получить текущего пользователя")
    @GetMapping("/me")
    public ResponseEntity<AdminLoginUserDto> getCurrentUser() {
        return ResponseEntity.ok(userService.getCurrentUserProfile());
    }
}
