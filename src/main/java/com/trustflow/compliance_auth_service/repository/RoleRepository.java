package com.trustflow.compliance_auth_service.repository;



import com.trustflow.compliance_auth_service.domain.*;
import com.trustflow.compliance_auth_service.domain.enums.*;
import org.springframework.data.jpa.repository.*;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(RoleType name);
}

