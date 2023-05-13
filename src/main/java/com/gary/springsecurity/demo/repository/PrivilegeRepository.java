package com.gary.springsecurity.demo.repository;

import com.gary.springsecurity.demo.entity.Privilege;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface PrivilegeRepository extends JpaRepository<Privilege,Integer> {
    Optional<Privilege> findByName(String name);
}
