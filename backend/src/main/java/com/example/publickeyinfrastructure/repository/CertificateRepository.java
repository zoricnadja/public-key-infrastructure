package com.example.publickeyinfrastructure.repository;

import com.example.publickeyinfrastructure.model.Certificate;
import com.example.publickeyinfrastructure.model.CertificateType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateRepository extends JpaRepository<Certificate, Long> {
    @Query("SELECT c FROM Certificate c WHERE " +
            "(c.type = 'ROOT' OR c.type = 'INTERMEDIATE') AND " +
            "c.isWithdrawn = false AND " +
            "c.issued <= CURRENT_TIMESTAMP AND " +
            "c.expires > CURRENT_TIMESTAMP AND " +
            "(c.subject.organization = :organization OR " +
            " c.subject.organization IN ('Public CA', 'Government CA'))")
    List<Certificate> findValidCAForRegularUser(@Param("organization") String organization);

    @Query("SELECT c FROM Certificate c WHERE " +
            "c.type IN :allowedTypes AND " +
            "(:organization IS NULL OR c.subject.organization = :organization) AND " +
            "c.isWithdrawn = false AND " +
            "c.issued <= CURRENT_TIMESTAMP AND " +
            "c.expires > CURRENT_TIMESTAMP")
    List<Certificate> findValidCAForAdminAndCA(
            @Param("allowedTypes") List<CertificateType> allowedTypes,
            @Param("organization") String organization
    );

    Optional<Certificate> findBySubject_CommonName(String commonName);
    Optional<Certificate> findBySerialNumber(String serialNumber);

    List<Certificate> findAllByTypeIn(List<CertificateType> types);
}
