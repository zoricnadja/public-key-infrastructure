package com.example.publickeyinfrastructure.service;

import com.example.publickeyinfrastructure.config.Constants;
import com.example.publickeyinfrastructure.keystore.ProjectKeyStore;
import com.example.publickeyinfrastructure.model.Certificate;
import com.example.publickeyinfrastructure.model.CertificateExtension;
import com.example.publickeyinfrastructure.model.CertificateType;
import com.example.publickeyinfrastructure.model.ExtensionType;
import com.example.publickeyinfrastructure.model.CertificateEntity;
import com.example.publickeyinfrastructure.model.Role;
import com.example.publickeyinfrastructure.model.User;
import com.example.publickeyinfrastructure.repository.CertificateRepository;
import jakarta.persistence.EntityNotFoundException;
import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Service
public class CertificateService {

    @Value("${keystore.path}")
    private String keystorePath;
    private final CertificateRepository certificateRepository;

    private static final Logger logger = LoggerFactory.getLogger(CertificateService.class);

    private final ProjectKeyStore projectKeyStore;

    @Autowired
    public CertificateService(CertificateRepository certificateRepository, ProjectKeyStore projectKeyStore) {
        this.certificateRepository = certificateRepository;
        this.projectKeyStore = projectKeyStore;
    }

    public KeyPair generateKeyPair() {
        KeyPairGenerator keyGen;
        try {
            keyGen = KeyPairGenerator.getInstance(Constants.KEY_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(String.format("%s algorithm not supported on this JVM", Constants.CRYPTO_ALGORITHM), e);
        }
        try{
            SecureRandom random = SecureRandom.getInstance(Constants.RANDOM_ALGORITHM, Constants.RANDOM_PROVIDER);
            keyGen.initialize(Constants.KEY_SIZE, random);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(String.format("%s algorithm not supported on this JVM", Constants.RANDOM_ALGORITHM), e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(String.format("%s provider not supported on this JVM", Constants.RANDOM_PROVIDER), e);
        }
    }

    public Certificate findBySerialNumber(String serialNumber){
        return certificateRepository.findBySerialNumber(serialNumber).orElseThrow(() -> new EntityNotFoundException("Certificate not found"));
    }

    public List<Certificate> findAllIssuers(){
        return certificateRepository.findAllByTypeIn(List.of(CertificateType.INTERMEDIATE, CertificateType.ROOT));
    }

//    public List<Certificate> getCACertificates(User user) {
//        List<CertificateType> allowedTypes = List.of(CertificateType.ROOT, CertificateType.INTERMEDIATE);
//
//        return switch (user.getRole()) {
//            case ADMIN ->
//                // Root admin može koristiti sve validne CA sertifikate
//                    certificateRepository.findValidCAForAdminAndCA(allowedTypes, null);
//            case CA_USER ->
//                // CA korisnik samo iz svoje organizacije
//                    certificateRepository.findValidCAForAdminAndCA(allowedTypes, user.getOrganization());
//            case USER ->
//                // Običan korisnik samo za End-Entity (koristi custom query)
//                    certificateRepository.findValidCAForRegularUser(user.getOrganization());
//            default -> List.of();
//        };
//    }

    /**
     * Provera digitalnog potpisa sertifikata
     */
//    public boolean checkCertificateChain(Certificate cert) {
//        try {
//            if (cert == null || cert.getCertificateEntity() == null) {
//                return false;
//            }
//
//            X509Certificate certHolder = cert.toX509Certificate();
//
//            PublicKey issuerPublicKey = cert.getCertificateEntity().getPublicKey();
//            if (issuerPublicKey == null) return false;
//
//            ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
//                    .build(issuerPublicKey);
//            if (!certHolder.isSignatureValid(verifier)) {
//                return false;
//            }
//
//            if (cert.getType() == CertificateType.ROOT) {
//                return cert.getCertificateEntity().getX500Name().equals(cert.getCertificateEntity().getX500Name());
//            }
//
//            Certificate issuerCert = certificateRepository.findByCertificateEntity(cert.getCertificateEntity());
//            if (issuerCert == null) return false;
//
//            return checkCertificateChain(issuerCert);
//
//        } catch (Exception e) {
//            e.printStackTrace();
//            return false;
//        }
//    }

    public boolean checkChain(Certificate certificate) {
        try {
            X500Name subjectName = certificate.getSubject().getX500Name();
            logger.debug("ovo je - {}", subjectName.toString());
            X500Name issuerName = certificate.getIssuer().getX500Name();
            logger.debug("ovo je - {}", issuerName.toString());

            if (certificate.getType() == CertificateType.ROOT && subjectName.equals(issuerName)) {
                logger.debug("ovo je - root deo" );
                certificate.toX509Certificate().verify(certificate.getSubject().getPublicKey());
                return true;
            }

            Optional<Certificate> parentOpt = certificateRepository.findBySubject_CommonName(issuerName.toString());

            if (parentOpt.isEmpty()) return false;
            logger.debug("ovo je - parent deo" );

            Certificate parent = parentOpt.get();
            logger.debug("ovo je - {}", parent.toString());

            X509Certificate parentCert = parent.toX509Certificate();
            logger.debug("ovo je - {}", parentCert.toString());

            if (parent.isDateValid()) return false;
            logger.debug("ovo je - validan deo" );

            if (Boolean.TRUE.equals(parent.getIsWithdrawn())) return false;
            logger.debug("ovo je - validan2 deo" );

            parentCert.verify(parent.getSubject().getPublicKey());
            logger.debug("ovo je - validan3 deo" );

            return checkChain(parent);

        } catch (Exception e) {
            return false;
        }
    }


    public Certificate createCertificate(Certificate request, Role subjectRole, String issuerSerialNumber) throws Exception {
        CertificateEntity issuer;
        CertificateEntity subject = request.getSubject();
        logger.debug("ovo je - {}", subject.toString());
        request.setSubject(subject);
        boolean isCA = checkIsCA(request);
        logger.debug("ovo je - {}", isCA);
        X509Certificate xCertificate;
        if(request.getType().equals(CertificateType.ROOT)) {
            if(isCA && subjectRole.equals(Role.ADMIN)) {
                createRootCertificateEntities(request);
                xCertificate = CertificateGenerator.generateRootCA(request);
            }
            else
                throw new IllegalArgumentException("You don't have permission to create Root CA Certificate");
        } else {
            //todo subject key
            issuer = generateCertificateEntity(request);
            Certificate issuerCertificate = findBySerialNumber(issuerSerialNumber);
            request.setIssuer(issuer);
            if (request.getType().equals(CertificateType.INTERMEDIATE) && isCA && (subjectRole.equals(Role.ADMIN) || subjectRole.equals(Role.CA_USER)))
                xCertificate = CertificateGenerator.generateIntermediateCA(request, issuerCertificate.toX509Certificate(), issuer.getPrivateKey());
            else
                xCertificate = CertificateGenerator.generateCertificate(request, issuerCertificate.toX509Certificate(), issuer.getPrivateKey());
        }

        request.setSerialNumber(xCertificate.getSerialNumber().toString());
        request.setSignature(xCertificate.getSignature());
        logger.debug("ovo je - {}", request);
        request = certificateRepository.save(request);
        logger.debug("ovo je - {}", request);
        projectKeyStore.loadOrCreate(keystorePath); // ucitaj postojeci ili kreiraj novi KS
        projectKeyStore.writeKeyEntry(String.format("Cert-%d", request.getIssuer().getId()), request.getIssuer().getPrivateKey(), xCertificate);
        projectKeyStore.save(keystorePath);

        return request;
    }

    private CertificateEntity generateCertificateEntity(Certificate request){

        CertificateEntity issuer = certificateRepository.findBySubject_CommonName(request.getSubject().getCommonName()).orElseThrow(() -> new EntityNotFoundException("Issuer doesn't exist")).getIssuer();
        Optional<PrivateKey> issuerKey = projectKeyStore.readPrivateKey(request.getSerialNumber());
        CertificateEntity generatedCertificateEntity = new CertificateEntity();
        generatedCertificateEntity.setEmail(issuer.getEmail());
        generatedCertificateEntity.setLocality(issuer.getLocality());
        generatedCertificateEntity.setOrganization(issuer.getOrganization());
        generatedCertificateEntity.setOrganizationalUnit(issuer.getOrganizationalUnit());
        generatedCertificateEntity.setCountry(issuer.getCountry());
        generatedCertificateEntity.setCommonName(issuer.getCommonName());
        generatedCertificateEntity.setState(issuer.getState());
        generatedCertificateEntity.setPrivateKey(issuerKey.get());
        generatedCertificateEntity.setPublicKey(issuer.getPublicKey());

        return generatedCertificateEntity;
    }
    private Certificate createRootCertificateEntities(Certificate certificate){

        CertificateEntity issuer = new CertificateEntity();
        CertificateEntity subject = certificate.getSubject();
        KeyPair keyPair = this.generateKeyPair();
        subject.setPublicKey(keyPair.getPublic());
        subject.setPrivateKey(keyPair.getPrivate());
        issuer.setPublicKey(keyPair.getPublic());
        issuer.setPrivateKey(keyPair.getPrivate());
        issuer.setEmail(subject.getEmail());
        issuer.setLocality(subject.getLocality());
        issuer.setOrganization(subject.getOrganization());
        issuer.setOrganizationalUnit(subject.getOrganizationalUnit());
        issuer.setCountry(subject.getCountry());
        issuer.setCommonName(subject.getCommonName());
        issuer.setState(subject.getState());

        certificate.setIssuer(issuer);
        certificate.setSubject(subject);
        return certificate;
    }

    private boolean checkIsCA(Certificate certificate) {
        if (certificate == null || certificate.getExtensions() == null) return false;

        Optional<CertificateExtension> extension = certificate.getExtensions().stream()
                .filter(ext -> ext.getExtensionType() == ExtensionType.BASIC_CONSTRAINTS)
                .findFirst();
        return extension.isPresent() && (new String(extension.get().getValue(), StandardCharsets.UTF_8)).equals("CA:true");

    }
}
