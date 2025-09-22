package com.example.publickeyinfrastructure.controller;

import com.example.publickeyinfrastructure.dto.CertificateDTO;
import com.example.publickeyinfrastructure.dto.UserDTO;
import com.example.publickeyinfrastructure.mapper.CertificateMapper;
import com.example.publickeyinfrastructure.model.Certificate;
import com.example.publickeyinfrastructure.model.User;
import com.example.publickeyinfrastructure.repository.UserRepository;
import com.example.publickeyinfrastructure.service.CertificateService;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;


import java.util.List;

@RestController
@CrossOrigin(origins = "https://localhost:4200")
@RequestMapping("/api/certificates")
public class CertificateController {

    private final CertificateService certificateService;
    private final CertificateMapper certificateMapper;
    private final UserRepository userRepository;

    @Autowired
    public CertificateController(CertificateService certificateService, CertificateMapper certificateMapper, UserRepository userRepository) {
        this.certificateService = certificateService;
        this.certificateMapper = certificateMapper;
        this.userRepository = userRepository;
    }

    @GetMapping("/issuers")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<List<CertificateDTO>> getIssuers(@RequestBody UserDTO dto) {
        User user = userRepository.findByEmail(dto.getEmail())
                .orElseThrow(() -> new EntityNotFoundException(
                        "User not found with email: " + dto.getEmail()));

        List<Certificate> caCertificates = certificateService.getCACertificates(user);

        List<CertificateDTO> response = caCertificates.stream()
                .map(certificateMapper::toDTO)
                .toList();

        return ResponseEntity.ok(response);
    }


    @PostMapping("/")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN', 'CA_USER')")
    public ResponseEntity<CertificateDTO> createCertificate(@RequestBody CertificateDTO certificateDTO) {
        return null;
    }
}