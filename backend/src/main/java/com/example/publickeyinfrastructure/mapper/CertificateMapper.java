package com.example.publickeyinfrastructure.mapper;

import com.example.publickeyinfrastructure.config.Constants;
import com.example.publickeyinfrastructure.dto.CertificateDTO;
import com.example.publickeyinfrastructure.dto.CreateCertificateRequest;
import com.example.publickeyinfrastructure.dto.ExtensionDTO;
import com.example.publickeyinfrastructure.keystore.ProjectKeyStore;
import com.example.publickeyinfrastructure.model.Certificate;
import com.example.publickeyinfrastructure.model.CertificateExtension;
import com.example.publickeyinfrastructure.model.Issuer;
import com.example.publickeyinfrastructure.model.Subject;
import com.example.publickeyinfrastructure.service.CertificateService;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class CertificateMapper {

    private static final Logger logger = LoggerFactory.getLogger(CertificateMapper.class);

    private final ModelMapper modelMapper;
    private final ExtensionMapper extensionMapper;
    private final CertificateService certificateService;
    private final ProjectKeyStore projectKeyStore;

    @Autowired
    public CertificateMapper(ExtensionMapper extensionMapper,
                             CertificateService certificateService,
                             ProjectKeyStore projectKeyStore) {
        this.extensionMapper = extensionMapper;
        this.certificateService = certificateService;
        this.projectKeyStore = projectKeyStore;
        this.modelMapper = new ModelMapper();
        configureMapper();
    }

    private void configureMapper() {
        // Mapiranje polja DTO-a preko lambda funkcija (sigurno, bez pristupa PublicKey)
        modelMapper.typeMap(Certificate.class, CertificateDTO.class)
                .addMapping(src -> src.getSubject() != null ? src.getSubject().getCommonName() : null,
                        CertificateDTO::setSubjectCN)
                .addMapping(src -> src.getSubject() != null ? src.getSubject().getOrganization() : null,
                        CertificateDTO::setSubjectO)
                .addMapping(src -> src.getSubject() != null ? src.getSubject().getOrganizationalUnit() : null,
                        CertificateDTO::setSubjectOU)
                .addMapping(src -> src.getIssuer() != null ? src.getIssuer().getCommonName() : null,
                        CertificateDTO::setIssuerCN)
                .addMapping(src -> src.getIssuer() != null ? src.getIssuer().getOrganization() : null,
                        CertificateDTO::setIssuerO)
                .addMapping(src -> src.getIssuer() != null ? src.getIssuer().getOrganizationalUnit() : null,
                        CertificateDTO::setIssuerOU);
    }

    public CertificateDTO toDTO(Certificate certificate) {
        if (certificate == null) return null;
        return modelMapper.map(certificate, CertificateDTO.class);
    }

    public Certificate fromRequest(CreateCertificateRequest request) {
        if (request == null) return null;

        Certificate certificate = modelMapper.map(request, Certificate.class);

        // Subject
        if (request.getSubject() != null) {
            Subject subject = new Subject();
            KeyPair keyPairSubject = certificateService.generateKeyPair();
            subject.setPublicKey(keyPairSubject.getPublic());
            subject.setCommonName(request.getSubject().getCommonName());
            subject.setOrganization(request.getSubject().getOrganization());
            subject.setOrganizationalUnit(request.getSubject().getOrganizationUnit());
            subject.setCountry(request.getSubject().getCountry());
            subject.setState(request.getSubject().getState());
            subject.setLocality(request.getSubject().getLocality());
            subject.setEmail(request.getSubject().getEmail());
            certificate.setSubject(subject);
        }

        // Issuer
        if (request.getIssuerSerialNumber() != null) {
            Certificate issuerCertificate = certificateService.findBySerialNumber(request.getIssuerSerialNumber());
            if (issuerCertificate == null) {
                throw new RuntimeException("Issuer certificate not found by serial number: " + request.getIssuerSerialNumber());
            }
            Issuer issuer = new Issuer();
            PrivateKey issuerKey = projectKeyStore.readPrivateKey(certificate.getSerialNumber(), Constants.ENTRY_PASSWORD);
            issuer.setPrivateKey(issuerKey);
            issuer.setPublicKey(issuerCertificate.getPublicKey());
            issuer.setCommonName(issuerCertificate.getSubject().getCommonName());
            issuer.setOrganization(issuerCertificate.getSubject().getOrganization());
            issuer.setOrganizationalUnit(issuerCertificate.getSubject().getOrganizationalUnit());
            issuer.setCountry(issuerCertificate.getSubject().getCountry());
            issuer.setState(issuerCertificate.getSubject().getState());
            issuer.setLocality(issuerCertificate.getSubject().getLocality());
            issuer.setEmail(issuerCertificate.getSubject().getEmail());
            certificate.setIssuer(issuer);
        }

        // Extensions
        if (request.getExtensions() != null && !request.getExtensions().isEmpty()) {
            List<CertificateExtension> extensions = request.getExtensions().stream()
                    .map(dto -> extensionMapper.fromDTO(dto, certificate))
                    .collect(Collectors.toList());
            certificate.setExtensions(extensions);
        }

        certificate.setIsWithdrawn(false);
        certificate.setVersion(3);
        certificate.setSignatureAlgorithm(Constants.SIGNATURE_ALGORITHM);

        return certificate;
    }
}
