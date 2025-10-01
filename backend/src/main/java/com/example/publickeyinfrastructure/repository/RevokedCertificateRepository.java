package com.example.publickeyinfrastructure.repository;

import com.example.publickeyinfrastructure.model.RevokedCertificate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.math.BigInteger;
import java.util.Optional;

@Repository
public interface RevokedCertificateRepository extends JpaRepository<RevokedCertificate, Long> {
    Optional<RevokedCertificate> findBySerialNumber(String serialNumber);
    Optional<RevokedCertificate> findBySerialNumberAndIssuerName(String serialNumber, String issuerName);
    boolean existsBySerialNumber(String serialNumber);
    boolean existsBySerialNumberAndIssuerName(String serialNumber, String issuerName);
}
