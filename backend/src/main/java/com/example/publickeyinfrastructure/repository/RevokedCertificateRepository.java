package com.example.publickeyinfrastructure.repository;

import com.example.publickeyinfrastructure.model.RevokedCertificate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RevokedCertificateRepository extends JpaRepository<RevokedCertificate, Long> {
    Optional<RevokedCertificate> findBySerialNumber(String serialNumber);
    Optional<RevokedCertificate> findBySerialNumberAndIssuerDn(String serialNumber, String issuerDn);
    boolean existsBySerialNumber(String serialNumber);
    boolean existsBySerialNumberAndIssuerDn(String serialNumber, String issuerDn);
    List<RevokedCertificate> findAllByIssuerDn(String issuerName);
}
