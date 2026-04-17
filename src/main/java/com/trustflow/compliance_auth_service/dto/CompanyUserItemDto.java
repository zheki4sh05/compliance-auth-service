package com.trustflow.compliance_auth_service.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CompanyUserItemDto {
    private String id;
    private String name;
    private String email;
    private String status;
    private String jobTitle;

    @JsonProperty("accessPermissions")
    private List<String> accessPermissions;

    private String createdAt;
}
