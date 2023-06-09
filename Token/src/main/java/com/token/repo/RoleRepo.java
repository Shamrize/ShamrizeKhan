package com.token.repo;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.token.model.ERole;
import com.token.model.Role;

@Repository
public interface RoleRepo extends JpaRepository<Role, Long> {

	Optional<Role> findByRoleName(ERole roleName);
	
}
