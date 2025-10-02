package com.example.publickeyinfrastructure.service;

import java.util.List;
import java.util.Optional;

import com.example.publickeyinfrastructure.model.Role;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.publickeyinfrastructure.model.User;
import com.example.publickeyinfrastructure.repository.UserRepository;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final CertificateService certificateService;

    @Autowired
    public UserService(UserRepository userRepository, CertificateService certificateService) {
        this.userRepository = userRepository;
        this.certificateService = certificateService;
    }

    public Optional<User> findByEmail(String email) {
        return this.userRepository.findByEmail(email);
    }

    public User save(User user) {
        return this.userRepository.save(user);
    }

    public List<User> findAllCAUsers() {
        return this.userRepository.findAllByRole(Role.CA_USER);
    }

    public List<String> findAllAssigned() {
        return this.userRepository.findAll().stream().flatMap(u -> u.getCertificateSerialNumbers().stream()).toList();
    }

    public User findById(Integer userId){
        return this.userRepository.findById(userId).orElseThrow(() -> new EntityNotFoundException("User not found"));
    }
}
