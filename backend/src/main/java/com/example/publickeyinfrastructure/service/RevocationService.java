package com.example.publickeyinfrastructure.service;

import com.example.publickeyinfrastructure.keystore.ProjectKeyStore;
import com.example.publickeyinfrastructure.model.RevocationReason;
import com.example.publickeyinfrastructure.model.RevokedCertificate;
import com.example.publickeyinfrastructure.repository.RevokedCertificateRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Optional;

@Service
public class RevocationService {

    @Value("${keystore.path}")
    private String keystorePath;
    private final ProjectKeyStore projectKeyStore;
    private final RevokedCertificateRepository revokedCertificateRepository;

    public RevocationService(RevokedCertificateRepository revokedCertificateRepository, ProjectKeyStore projectKeyStore) {
        this.projectKeyStore = projectKeyStore;
        this.revokedCertificateRepository = revokedCertificateRepository;
    }

    public void revokeCertificate(String serialNumber, RevocationReason reason) {
        if (!revokedCertificateRepository.existsBySerialNumber(serialNumber)) {
            projectKeyStore.loadOrCreate(keystorePath);
            Optional<X509Certificate> certOpt = projectKeyStore.getCertificateBySerialNumber(serialNumber);
            if (certOpt.isEmpty()) {
                throw new IllegalArgumentException("Certificate with serial number " + serialNumber + " not found in keystore.");
            }

            X509Certificate certificate = certOpt.get();
            if (certificate.getNotAfter().before(new Date())) {
                throw new IllegalArgumentException("Certificate with serial number " + serialNumber + " is already expired.");
            }

            revokedCertificateRepository.save(new RevokedCertificate(null, serialNumber, certificate.getIssuerX500Principal().getName(), reason, null));
        }
    }

    public boolean isCertificateRevoked(String serialNumber) {
        return revokedCertificateRepository.existsBySerialNumber(serialNumber);
    }
}
