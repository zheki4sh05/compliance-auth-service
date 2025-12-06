package com.trustflow.compliance_auth_service.service;

import com.trustflow.compliance_auth_service.domain.*;
import com.trustflow.compliance_auth_service.domain.enums.*;
import com.trustflow.compliance_auth_service.dto.*;
import com.trustflow.compliance_auth_service.repository.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.*;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional(readOnly = true)
    public List<UserDto> findAll() {
        log.info("Fetching all users");
        return userRepository.findAll().stream()
                .map(this::mapToDto)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(readOnly = true)
    public UserDto findById(Long id) {
        log.info("Fetching user by id: {}", id);
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + id));
        return mapToDto(user);
    }

    @Override
    @Transactional(readOnly = true)
    public UserDto findByUsername(String username) {
        log.info("Fetching user by username: {}", username);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
        return mapToDto(user);
    }

    @Override
    @Transactional
    public UserDto create(UserDto userDto) {
        log.info("Creating new user: {}", userDto.getUsername());

        // Проверка на существование пользователя
        if (userRepository.findByUsername(userDto.getUsername()).isPresent()) {
            throw new IllegalArgumentException("User already exists with username: " + userDto.getUsername());
        }

        if (userRepository.findByEmail(userDto.getEmail()).isPresent()) {
            throw new IllegalArgumentException("User already exists with email: " + userDto.getEmail());
        }

        // Создание пользователя
        User user = User.builder()
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .email(userDto.getEmail())
                .enabled(userDto.getEnabled() != null ? userDto.getEnabled() : true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .build();

        // Установка ролей
        if (userDto.getRoles() != null && !userDto.getRoles().isEmpty()) {
            Set<Role> roles = userDto.getRoles().stream()
                    .map(roleType -> roleRepository.findByName(roleType)
                            .orElseThrow(() -> new IllegalArgumentException("Role not found: " + roleType)))
                    .collect(Collectors.toSet());
            user.setRoles(roles);
        } else {
            // По умолчанию роль MANAGER
            Role defaultRole = roleRepository.findByName(RoleType.ROLE_MANAGER)
                    .orElseThrow(() -> new IllegalStateException("Default role MANAGER not found"));
            user.setRoles(Set.of(defaultRole));
        }

        User savedUser = userRepository.save(user);
        log.info("Successfully created user: {}", savedUser.getUsername());

        return mapToDto(savedUser);
    }

    @Override
    @Transactional
    public UserDto update(Long id, UserDto userDto) {
        log.info("Updating user with id: {}", id);

        User user = userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + id));

        // Обновление полей
        if (userDto.getEmail() != null && !userDto.getEmail().equals(user.getEmail())) {
            if (userRepository.findByEmail(userDto.getEmail()).isPresent()) {
                throw new IllegalArgumentException("Email already in use: " + userDto.getEmail());
            }
            user.setEmail(userDto.getEmail());
        }

        if (userDto.getPassword() != null && !userDto.getPassword().isEmpty()) {
            user.setPassword(passwordEncoder.encode(userDto.getPassword()));
        }

        if (userDto.getEnabled() != null) {
            user.setEnabled(userDto.getEnabled());
        }

        // Обновление ролей
        if (userDto.getRoles() != null && !userDto.getRoles().isEmpty()) {
            Set<Role> roles = userDto.getRoles().stream()
                    .map(roleType -> roleRepository.findByName(roleType)
                            .orElseThrow(() -> new IllegalArgumentException("Role not found: " + roleType)))
                    .collect(Collectors.toSet());
            user.setRoles(roles);
        }

        User updatedUser = userRepository.save(user);
        log.info("Successfully updated user: {}", updatedUser.getUsername());

        return mapToDto(updatedUser);
    }

    @Override
    @Transactional
    public void delete(Long id) {
        log.info("Deleting user with id: {}", id);

        User user = userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with id: " + id));

        userRepository.delete(user);
        log.info("Successfully deleted user: {}", user.getUsername());
    }

    @Override
    @Transactional(readOnly = true)
    public UserDto getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new IllegalStateException("No authenticated user found");
        }

        String username = authentication.getName();
        return findByUsername(username);
    }

    // Helper method для маппинга Entity -> DTO
    private UserDto mapToDto(User user) {
        UserDto dto = new UserDto();
        dto.setId(user.getId());
        dto.setUsername(user.getUsername());
        dto.setEmail(user.getEmail());
        dto.setEnabled(user.getEnabled());
        dto.setCreatedAt(user.getCreatedAt());
        dto.setUpdatedAt(user.getUpdatedAt());

        if (user.getRoles() != null) {
            dto.setRoles(user.getRoles().stream()
                    .map(Role::getName)
                    .collect(Collectors.toSet()));
        }

        return dto;
    }




    private List<String> getPermissionsByRole(Set<Role> roles) {
        // Мапинг ролей на права доступа
        if (roles.stream().anyMatch(r -> r.getName() == RoleType.ROLE_EXECUTIVE)) {
            return List.of("VIEW_CASES", "EDIT_CASES", "DELETE_CASES", "ASSIGN_TASKS",
                    "MANAGE_USERS", "VIEW_REPORTS", "MANAGE_SETTINGS");
        } else if (roles.stream().anyMatch(r -> r.getName() == RoleType.ROLE_SUPERVISOR)) {
            return List.of("VIEW_CASES", "EDIT_CASES", "ASSIGN_TASKS",
                    "VIEW_REPORTS", "MANAGE_TEAM");
        } else {
            return List.of("VIEW_CASES", "EDIT_CASES", "ASSIGN_TASKS");
        }
    }

}

