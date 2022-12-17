package com.skomane.authentication.repository;

import com.skomane.authentication.enums.ERole;
import com.skomane.authentication.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
