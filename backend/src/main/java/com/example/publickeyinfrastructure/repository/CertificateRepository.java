package com.example.publickeyinfrastructure.repository;

import com.example.publickeyinfrastructure.model.Certificate;
import com.example.publickeyinfrastructure.model.CertificateType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateRepository extends JpaRepository<Certificate, Long> {
    Optional<Certificate> findBySubject_CommonName(String commonName);
    Optional<Certificate> findBySerialNumber(String serialNumber);

    List<Certificate> findAllByTypeIn(List<CertificateType> types);
}
