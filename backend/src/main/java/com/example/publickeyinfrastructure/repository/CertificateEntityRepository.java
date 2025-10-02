package com.example.publickeyinfrastructure.repository;

import com.example.publickeyinfrastructure.model.CertificateEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CertificateEntityRepository extends JpaRepository<CertificateEntity, Long> {
}
