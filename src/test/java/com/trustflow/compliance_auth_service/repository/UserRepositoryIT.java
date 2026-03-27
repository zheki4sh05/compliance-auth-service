package com.trustflow.compliance_auth_service.repository;

import com.trustflow.compliance_auth_service.AbstractIntegrationTest;
import com.trustflow.compliance_auth_service.domain.Role;
import com.trustflow.compliance_auth_service.domain.User;
import com.trustflow.compliance_auth_service.domain.enums.RoleType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class UserRepositoryIT extends AbstractIntegrationTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Test
    void shouldSaveAndFindUser() {
        Role role = Role.builder()
                .name(RoleType.MANAGER)
                .description("Manager role")
                .build();
        roleRepository.save(role);

        User user = User.builder()
                .username("testuser")
                .email("test@example.com")
                .password("password")
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .roles(Set.of(role))
                .build();

        User saved = userRepository.save(user);

        Optional<User> found = userRepository.findById(saved.getId());
        assertThat(found).isPresent();
        assertThat(found.get().getUsername()).isEqualTo("testuser");
        assertThat(found.get().getEmail()).isEqualTo("test@example.com");
    }

    @Test
    void shouldFindUserByUsername() {
        Role role = Role.builder()
                .name(RoleType.MANAGER)
                .description("Manager role")
                .build();
        roleRepository.save(role);

        User user = User.builder()
                .username("johndoe")
                .email("john@example.com")
                .password("password")
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .roles(Set.of(role))
                .build();

        userRepository.save(user);

        Optional<User> found = userRepository.findByUsername("johndoe");
        assertThat(found).isPresent();
        assertThat(found.get().getEmail()).isEqualTo("john@example.com");
    }

    @Test
    void shouldFindUserByEmail() {
        Role role = Role.builder()
                .name(RoleType.MANAGER)
                .description("Manager role")
                .build();
        roleRepository.save(role);

        User user = User.builder()
                .username("alice")
                .email("alice@example.com")
                .password("password")
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .roles(Set.of(role))
                .build();

        userRepository.save(user);

        Optional<User> found = userRepository.findByEmail("alice@example.com");
        assertThat(found).isPresent();
        assertThat(found.get().getUsername()).isEqualTo("alice");
    }
}