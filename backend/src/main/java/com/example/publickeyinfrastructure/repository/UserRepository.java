package com.example.publickeyinfrastructure.repository;

import java.util.List;
import java.util.Optional;

import com.example.publickeyinfrastructure.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.publickeyinfrastructure.model.User;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByEmail(String email);

    List<User> findAllByRole(Role role);
}