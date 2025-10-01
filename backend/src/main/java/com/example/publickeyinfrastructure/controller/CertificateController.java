package com.example.publickeyinfrastructure.controller;

import com.example.publickeyinfrastructure.dto.CertificateResponse;
import com.example.publickeyinfrastructure.dto.CreateCertificateRequest;
import com.example.publickeyinfrastructure.dto.RevocationRequest;
import com.example.publickeyinfrastructure.mapper.CertificateMapper;
import com.example.publickeyinfrastructure.model.Certificate;
import com.example.publickeyinfrastructure.model.Role;
import com.example.publickeyinfrastructure.repository.UserRepository;
import com.example.publickeyinfrastructure.service.CertificateService;
import com.example.publickeyinfrastructure.service.RevocationService;
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


import java.util.List;

@RestController
@RequestMapping("/api/v1/certificates")
public class CertificateController {
    private static final Logger logger = LoggerFactory.getLogger(CertificateController.class);
    private final CertificateService certificateService;
    private final CertificateMapper certificateMapper;
    private final UserRepository userRepository;
    private final RevocationService revocationService;

    @Autowired
    public CertificateController(
            CertificateService certificateService,
            CertificateMapper certificateMapper,
            UserRepository userRepository,
            RevocationService revocationService
    ) {
        this.certificateService = certificateService;
        this.certificateMapper = certificateMapper;
        this.userRepository = userRepository;
        this.revocationService = revocationService;
    }

    @GetMapping("/issuers")
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN', 'ROLE_CA_USER')")
    public ResponseEntity<List<CertificateResponse>> getIssuers(@AuthenticationPrincipal Jwt jwt) {
        String email = jwt.getClaimAsString("email");
        userRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException(
                        "User not found with email: " + email));

        List<Certificate> caCertificates = certificateService.findAllIssuers();
        return ResponseEntity.ok(caCertificates.stream().map(certificateMapper::toDto).toList());
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('USER', 'ADMIN', 'CA_USER')")
    public ResponseEntity<CertificateResponse> createCertificate(@RequestBody CreateCertificateRequest request, Authentication authentication) throws Exception {
        Role role = RoleUtil.extraxtRole(authentication);
        Certificate certificate = this.certificateService.createCertificate(certificateMapper.toEntity(request), role, request.getIssuerSerialNumber());
        return ResponseEntity.status(HttpStatus.CREATED).body(certificateMapper.toDto(certificate));
    }

    @PostMapping("/revoke")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<String> revokeCertificate(@RequestBody RevocationRequest request) {
        try {
            this.revocationService.revokeCertificate(request.getSerialNumber(), request.getReason());
            return ResponseEntity.ok("Certificate with serial number " + request.getSerialNumber() + " has been revoked.");
        } catch (EntityNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(e.getMessage());
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
        } catch (Exception e) {
            logger.error("Error revoking certificate: ", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An error occurred while revoking the certificate.");
        }
    }

    @GetMapping("/is-revoked")
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN', 'ROLE_CA_USER')")
    public ResponseEntity<String> isCertificateRevoked(@RequestParam String serialNumber) {
        boolean isRevoked = this.revocationService.isCertificateRevoked(serialNumber);
        if (isRevoked) {
            return ResponseEntity.ok("Certificate with serial number " + serialNumber + " is revoked.");
        } else {
            return ResponseEntity.ok("Certificate with serial number " + serialNumber + " is not revoked.");
        }
    }
}