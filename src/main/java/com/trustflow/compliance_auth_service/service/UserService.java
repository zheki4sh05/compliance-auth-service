package com.trustflow.compliance_auth_service.service;


import com.trustflow.compliance_auth_service.dto.*;

import java.util.List;

public interface UserService {
    List<UserDto> findAll();
    UserDto findById(Long id);
    UserDto findByUsername(String username);
    UserDto create(UserDto userDto);
    UserDto update(Long id, UserDto userDto);
    void delete(Long id);
    UserDto getCurrentUser();

}

