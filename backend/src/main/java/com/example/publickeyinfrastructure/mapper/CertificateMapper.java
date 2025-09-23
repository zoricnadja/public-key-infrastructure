package com.example.publickeyinfrastructure.mapper;

import com.example.publickeyinfrastructure.config.Constants;
import com.example.publickeyinfrastructure.controller.CertificateController;
import com.example.publickeyinfrastructure.dto.CertificateDTO;
import com.example.publickeyinfrastructure.dto.CreateCertificateRequest;
import com.example.publickeyinfrastructure.dto.ExtensionDTO;
import com.example.publickeyinfrastructure.keystore.ProjectKeyStore;
import com.example.publickeyinfrastructure.model.Certificate;
import com.example.publickeyinfrastructure.model.CertificateExtension;
import com.example.publickeyinfrastructure.model.Issuer;
import com.example.publickeyinfrastructure.model.Subject;
import com.example.publickeyinfrastructure.service.CertificateService;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.modelmapper.Converter;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.StringWriter;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
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
    public CertificateMapper(ExtensionMapper extensionMapper, CertificateService certificateService, ProjectKeyStore projectKeyStore) {
        this.extensionMapper = extensionMapper;
        this.certificateService = certificateService;
        this.projectKeyStore = projectKeyStore;
        this.modelMapper = new ModelMapper();
        configureMapper();
    }

    private void configureMapper() {
//        Converter<Certificate, String> certToPemConverter = context -> {
//            Certificate cert = context.getSource();
//            if (cert == null) return null;
//
//            try (StringWriter sw = new StringWriter(); PemWriter pw = new PemWriter(sw)) {
//                pw.writeObject(new PemObject("CERTIFICATE", cert.toX509Certificate().getEncoded()));
//                return sw.toString();
//            } catch (Exception e) {
//                throw new RuntimeException("Failed to convert certificate to PEM", e);
//            }
//        };

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
        if (request.getIssuerSerialNumber() != null) {
            logger.debug("stampaj {}", request.getIssuerSerialNumber());
            Certificate issuerCertificate = certificateService.findBySerialNumber(request.getIssuerSerialNumber());
            if (issuerCertificate == null) {
                throw new RuntimeException("Issuer certificate not found by serial number: " + request.getIssuerSerialNumber());
            }
            Issuer issuer = new Issuer();
            PrivateKey issuerKey = projectKeyStore.readPrivateKey(certificate.getSerialNumber(), Constants.ENTRY_PASSWORD);
            issuer.setPublicKey(issuerCertificate.getPublicKey());
            issuer.setEmail(issuerCertificate.getSubject().getEmail());
            issuer.setLocality(issuerCertificate.getSubject().getLocality());
            issuer.setOrganization(issuerCertificate.getSubject().getOrganization());
            issuer.setOrganizationalUnit(issuerCertificate.getSubject().getOrganizationalUnit());
            issuer.setCountry(issuerCertificate.getSubject().getCountry());
            issuer.setCommonName(issuerCertificate.getSubject().getCommonName());
            issuer.setState(issuerCertificate.getSubject().getState());
            issuer.setPrivateKey(issuerKey);
            issuer.setPublicKey(issuerCertificate.getPublicKey());
            certificate.setIssuer(issuer);
        } else {
//            if (certificate.getSubject() != null) {
//                Issuer selfIssuer = createIssuerFromSubject(certificate.getSubject());
//                certificate.setIssuer(selfIssuer);
//            }
        }

        if (request.getExtensions() != null && !request.getExtensions().isEmpty()) {
            mapExtensionsToEntity(certificate, request.getExtensions());
        }

        certificate.setIsWithdrawn(false);
        certificate.setVersion(3);
        certificate.setSignatureAlgorithm(Constants.SIGNATURE_ALGORITHM);

        return certificate;
    }

    private Issuer createIssuerFromSubject(Subject subject) {
        Issuer issuer = new Issuer();
        issuer.setCommonName(subject.getCommonName());
        issuer.setOrganization(subject.getOrganization());
        issuer.setOrganizationalUnit(subject.getOrganizationalUnit());
        issuer.setCountry(subject.getCountry());
        issuer.setState(subject.getState());
        issuer.setLocality(subject.getLocality());
        issuer.setEmail(subject.getEmail());
        return issuer;
    }

    private void mapExtensionsToEntity(Certificate certificate, List<ExtensionDTO> extensionDTOs) {
        if (extensionDTOs == null || extensionDTOs.isEmpty()) {
            return;
        }

        List<CertificateExtension> extensions = extensionDTOs.stream()
                .map(dto -> {
                    try {
                        return extensionMapper.fromDTO(dto, certificate);
                    } catch (Exception e) {
                        throw new RuntimeException("Failed to map extension with OID: " + dto.getOid(), e);
                    }
                })
                .collect(Collectors.toList());

        certificate.setExtensions(extensions);
    }
}
