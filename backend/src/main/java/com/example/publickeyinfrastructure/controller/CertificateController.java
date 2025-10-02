package com.example.publickeyinfrastructure.controller;

import com.example.publickeyinfrastructure.dto.CertificateResponse;
import com.example.publickeyinfrastructure.dto.CreateCertificateRequest;
import com.example.publickeyinfrastructure.mapper.CertificateMapper;
import com.example.publickeyinfrastructure.model.Certificate;
import com.example.publickeyinfrastructure.model.CertificateType;
import com.example.publickeyinfrastructure.model.Role;
import com.example.publickeyinfrastructure.repository.UserRepository;
import com.example.publickeyinfrastructure.service.CertificateService;
import com.example.publickeyinfrastructure.util.RoleUtil;
import jakarta.persistence.EntityNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;


import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/certificates")
public class CertificateController {
    private static final Logger logger = LoggerFactory.getLogger(CertificateController.class);
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
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN', 'ROLE_CA_USER')")
    public ResponseEntity<List<CertificateResponse>> getIssuers(@AuthenticationPrincipal Jwt jwt) {
        String email = jwt.getClaimAsString("email");
        userRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException(
                        "User not found with email: " + email));

        Map<CertificateType, List<X509Certificate>> caCertificates = certificateService.findAllIssuers();

        return ResponseEntity.ok(
                caCertificates.entrySet().stream()
                        .flatMap(entry -> entry.getValue().stream()
                                .map(cert -> certificateMapper.toDto(entry.getKey(), cert)))
                        .toList()
        );

    }

    @PostMapping
    @PreAuthorize("hasAnyRole('USER', 'ADMIN', 'CA_USER')")
    public ResponseEntity<CertificateResponse> createCertificate(@RequestBody CreateCertificateRequest request, Authentication authentication) throws Exception {
        Role role = RoleUtil.extraxtRole(authentication);
        Certificate certificate = this.certificateService.createCertificate(certificateMapper.toEntity(request), role, request.getIssuerSerialNumber(), request.getIssuerCertificateType());
        return ResponseEntity.status(HttpStatus.CREATED).body(certificateMapper.toDto(certificate));
    }
}