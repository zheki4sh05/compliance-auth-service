package com.trustflow.compliance_auth_service.service;


import com.trustflow.compliance_auth_service.dto.*;

import java.util.List;
import java.util.UUID;

public interface UserService {
    List<UserDto> findAll();
    UserDto findById(UUID id);
    UserDto findByUsername(String username);
    UserDto create(UserDto userDto);
    UserDto update(UUID id, UserDto userDto);
    void delete(UUID id);
    UserDto getCurrentUser();
    AdminLoginUserDto getCurrentUserProfile();

}

