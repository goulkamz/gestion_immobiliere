package com.immobilier.gestionImmobiliere.donnees.roles.repository;

import com.immobilier.gestionImmobiliere.donnees.roles.model.ERole;
import com.immobilier.gestionImmobiliere.donnees.roles.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByLibelleRole(ERole libelleRole);
    Boolean existsByLibelleRole(ERole libelleRole);
}
