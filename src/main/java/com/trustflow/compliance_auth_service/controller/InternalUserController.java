package com.trustflow.compliance_auth_service.controller;

import com.trustflow.compliance_auth_service.dto.UserDto;
import com.trustflow.compliance_auth_service.service.UserService;
import io.swagger.v3.oas.annotations.Hidden;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.UUID;

@Hidden
@RestController
@RequestMapping("/api/internal/users")
@RequiredArgsConstructor
public class InternalUserController {

    private final UserService userService;

    @GetMapping("/{id}")
    public ResponseEntity<UserDto> getUserByIdForInternalUse(
            @PathVariable UUID id,
            HttpServletRequest request) {
        validateLocalRequest(request);
        return ResponseEntity.ok(userService.findById(id));
    }

    private void validateLocalRequest(HttpServletRequest request) {
        String remoteAddress = request.getRemoteAddr();
        if (remoteAddress == null || remoteAddress.isBlank()) {
            throw new AccessDeniedException("Доступ разрешен только для локальных сервисов");
        }

        try {
            InetAddress address = InetAddress.getByName(remoteAddress);
            if (!address.isLoopbackAddress()) {
                throw new AccessDeniedException("Доступ разрешен только для локальных сервисов");
            }
        } catch (UnknownHostException ex) {
            throw new AccessDeniedException("Доступ разрешен только для локальных сервисов");
        }
    }
}
