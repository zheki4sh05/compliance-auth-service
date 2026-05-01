package com.trustflow.compliance_auth_service.service;


import com.trustflow.compliance_auth_service.dto.*;

import java.util.UUID;

public interface UserService {
    CompanyUsersResponseDto findAllByCompanyId(String companyId);
    UserDto findById(UUID id);
    UserBasicInfoDto findBasicInfoById(UUID id);
    UserDto findByUsername(String username);
    UserDto create(UserDto userDto);
    UserDto update(UUID id, UserProfileUpdateRequestDto userProfileUpdateRequestDto);
    UserStatusDto updateUserStatus(UUID id, String companyId, UserStatusDto userStatusDto);
    void delete(UUID id);
    UserDto getCurrentUser();
    AdminLoginUserDto getCurrentUserProfile();

}

