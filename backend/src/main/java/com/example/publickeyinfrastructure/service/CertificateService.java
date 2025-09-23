package com.example.publickeyinfrastructure.service;

import com.example.publickeyinfrastructure.config.Constants;
import com.example.publickeyinfrastructure.controller.CertificateController;
import com.example.publickeyinfrastructure.keystore.ProjectKeyStore;
import com.example.publickeyinfrastructure.model.Certificate;
import com.example.publickeyinfrastructure.model.CertificateExtension;
import com.example.publickeyinfrastructure.model.CertificateType;
import com.example.publickeyinfrastructure.model.ExtensionType;
import com.example.publickeyinfrastructure.model.Issuer;
import com.example.publickeyinfrastructure.model.Role;
import com.example.publickeyinfrastructure.model.Subject;
import com.example.publickeyinfrastructure.model.User;
import com.example.publickeyinfrastructure.repository.CertificateRepository;
import jakarta.persistence.EntityNotFoundException;
import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

@Service
public class CertificateService {


    private CertificateRepository certificateRepository;

    private static final Logger logger = LoggerFactory.getLogger(CertificateService.class);

    private ProjectKeyStore projectKeyStore;

    @Autowired
    public CertificateService(CertificateRepository certificateRepository, ProjectKeyStore projectKeyStore) {
        this.certificateRepository = certificateRepository;
        this.projectKeyStore = projectKeyStore;
    }

    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            logger.debug("gen {}", keyGen);
            SecureRandom random = SecureRandom.getInstanceStrong(); // koristi strong RNG
            keyGen.initialize(Constants.KEY_SIZE);

            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("RSA algorithm not supported on this JVM", e);
        }
    }

    public Certificate findBySerialNumber(String serialNumber){
        return certificateRepository.findBySerialNumber(serialNumber).orElseThrow(() -> new EntityNotFoundException("Certificate not found"));
    }

//    public List<Certificate> getAvailableCACertificates(User user, CertificateType requestedType) {
//        switch (user.getRole()) {
//            case ADMIN:
//                return getCAForRootAdmin(requestedType);
//            case CA_USER:
//                return getCAForCAUser(user, requestedType);
//            case REGULAR_USER:
//                return getCAForRegularUser(user, requestedType);
//            default:
//                return List.of();
//        }
//    }

    /**
     * Root CA Admin može koristiti sve validne CA sertifikate
     */
//    private List<Certificate> getCAForRootAdmin(CertificateType requestedType) {
//        // Direktno iz baze - već filtrirani validni sertifikati
//        return certificateRepository.findAllValidCACertificates();
//    }

    /**
     * CA korisnik može koristiti samo CA sertifikate iz svog lanca i svoje organizacije
     */
//    private List<Certificate> getCAForCAUser(User user, CertificateType requestedType) {
//        // Direktno iz baze sa filterom organizacije - već validni sertifikati
//        List<Certificate> validCAs = certificateRepository.findValidCAByOrganization(
//                user.getOrganization()
//        );
//
//        // Za intermediate i end-entity sertifikate, korisnik može koristiti
//        // bilo koji CA iz svog lanca (Root ili Intermediate) - već je filtrirano u query-ju
//        if (requestedType == CertificateType.INTERMEDIATE_CA ||
//                requestedType == CertificateType.END_ENTITY) {
//            return validCAs;
//        }
//
//        return validCAs;
//    }
//
//    /**
//     * Običan korisnik može birati iz dostupnih CA sertifikata
//     * (moguce ogranicenje po organizaciji ili javni CA)
//     */
//    private List<Certificate> getCAForRegularUser(User user, CertificateType requestedType) {
//        // Običan korisnik može da zatraži samo End-Entity sertifikat
//        if (requestedType != CertificateType.END_ENTITY) {
//            return List.of(); // Nema dozvolu za CA sertifikate
//        }
//
//        // Direktno iz baze - kombinuje organizacione i javne CA, već validne
//        return certificateRepository.findValidCAForRegularUser(user.getOrganization());
//    }

    /**
     * Alternativno - koristi universalnu metodu sa parametrima
     */
    public List<Certificate> getCACertificates(User user) {
        List<CertificateType> allowedTypes = List.of(CertificateType.ROOT, CertificateType.INTERMEDIATE);

        return switch (user.getRole()) {
            case ADMIN ->
                // Root admin može koristiti sve validne CA sertifikate
                    certificateRepository.findValidCAForAdminAndCA(allowedTypes, null);
            case CA_USER ->
                // CA korisnik samo iz svoje organizacije
                    certificateRepository.findValidCAForAdminAndCA(allowedTypes, user.getOrganization());
            case USER ->
                // Običan korisnik samo za End-Entity (koristi custom query)
                    certificateRepository.findValidCAForRegularUser(user.getOrganization());
            default -> List.of();
        };
    }

    /**
     * Provera digitalnog potpisa sertifikata
     */
//    public boolean checkCertificateChain(Certificate cert) {
//        try {
//            if (cert == null || cert.getIssuer() == null) {
//                return false;
//            }
//
//            X509Certificate certHolder = cert.toX509Certificate();
//
//            PublicKey issuerPublicKey = cert.getIssuer().getPublicKey();
//            if (issuerPublicKey == null) return false;
//
//            ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
//                    .build(issuerPublicKey);
//            if (!certHolder.isSignatureValid(verifier)) {
//                return false;
//            }
//
//            if (cert.getType() == CertificateType.ROOT) {
//                return cert.getSubject().getX500Name().equals(cert.getIssuer().getX500Name());
//            }
//
//            Certificate issuerCert = certificateRepository.findBySubject(cert.getIssuer());
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
            X500Name issuerName = certificate.getIssuer().getX500Name();

            if (certificate.getType() == CertificateType.ROOT && subjectName.equals(issuerName)) {
                certificate.toX509Certificate().verify(certificate.getIssuer().getPublicKey());
                return true;
            }

            Optional<Certificate> parentOpt = certificateRepository.findBySubject_CommonName(issuerName.toString());
            if (parentOpt.isEmpty()) return false;

            Certificate parent = parentOpt.get();
            X509Certificate parentCert = parent.toX509Certificate();

            if (parent.isValid()) return false;

            if (Boolean.TRUE.equals(parent.getIsWithdrawn())) return false;

            parentCert.verify(parent.getIssuer().getPublicKey());

            return checkChain(parent);

        } catch (Exception e) {
            return false;
        }
    }


    public Certificate createCertificate(Certificate certificateRequest, Role subjectRole, String issuerAlias) throws Exception {
        Issuer issuer;
        Subject subject = certificateRequest.getSubject();
        certificateRequest.setSubject(subject);
        CertificateType type;
        Optional<CertificateExtension> bcExtension = getBasicConstraints(certificateRequest);
        X509Certificate xCertificate;
        if (certificateRequest.getIssuer() != null) {
            issuer = generateIssuer(certificateRequest);
            certificateRequest.setIssuer(issuer);
            Certificate issuerCertificate = findBySerialNumber(issuerAlias);

            if(bcExtension.isPresent() && bcExtension.get().getValueString().equals("CA:false")){
                xCertificate = CertificateGenerator.generateEndEntity(certificateRequest, issuerCertificate.toX509Certificate(), issuer.getPrivateKey());
                type = CertificateType.END_ENTITY;
            } else if(bcExtension.isPresent() && bcExtension.get().getValueString().equals("CA:true") && !subjectRole.equals(Role.USER)){
                type = CertificateType.INTERMEDIATE;
                xCertificate = CertificateGenerator.generateIntermediateCA(certificateRequest, issuerCertificate.toX509Certificate(), issuer.getPrivateKey());
            } else{
                throw new IllegalArgumentException("User cannot create intermediate certificate");
            }
        }
        else {
            KeyPair keyPair = generateKeyPair();
            issuer = new Issuer();
            subject.setPublicKey(keyPair.getPublic());
            issuer.setPublicKey(subject.getPublicKey());
            issuer.setEmail(subject.getEmail());
            issuer.setLocality(subject.getLocality());
            issuer.setOrganization(subject.getOrganization());
            issuer.setOrganizationalUnit(subject.getOrganizationalUnit());
            issuer.setCountry(subject.getCountry());
            issuer.setCommonName(subject.getCommonName());
            issuer.setState(subject.getState());
            issuer.setPrivateKey(keyPair.getPrivate());
            certificateRequest.setIssuer(issuer);
            xCertificate = CertificateGenerator.generateRootCA(certificateRequest);
            type = CertificateType.ROOT;
        }


        Certificate certificate = new Certificate();
        certificate.setSerialNumber(xCertificate.getSerialNumber().toString());
        certificate.setSignature(xCertificate.getSignature());
        certificate.setIssuer(issuer);
        certificate.setSubject(subject);
        certificate.setPublicKey(xCertificate.getPublicKey());
        certificate.setIssued(xCertificate.getNotBefore());
        certificate.setExpires(xCertificate.getNotAfter());
        certificate.setType(type);
        certificate = certificateRepository.save(certificate);
        projectKeyStore.load("keystore.jks", Constants.ENTRY_PASSWORD); // ucitaj postojeci ili kreiraj novi KS
        projectKeyStore.writeKeyEntry(issuer.getCommonName(), issuer.getPrivateKey(), Constants.ENTRY_PASSWORD, xCertificate);
        projectKeyStore.save("keystore.jks", Constants.ENTRY_PASSWORD);


        return certificate;
    }

    private Issuer generateIssuer(Certificate certificateRequest){
        Subject issuer = certificateRepository.findById(certificateRequest.getIssuer().getId()).get().getSubject();
        PrivateKey issuerKey = projectKeyStore.readPrivateKey(certificateRequest.getSerialNumber(), Constants.ENTRY_PASSWORD);
        Issuer generatedIssuer = new Issuer();
        generatedIssuer.setEmail(issuer.getEmail());
        generatedIssuer.setLocality(issuer.getLocality());
        generatedIssuer.setOrganization(issuer.getOrganization());
        generatedIssuer.setOrganizationalUnit(issuer.getOrganizationalUnit());
        generatedIssuer.setCountry(issuer.getCountry());
        generatedIssuer.setCommonName(issuer.getCommonName());
        generatedIssuer.setState(issuer.getState());
        generatedIssuer.setPrivateKey(issuerKey);
        generatedIssuer.setPublicKey(issuer.getPublicKey());

        return generatedIssuer;
    }

    public static Optional<CertificateExtension> getBasicConstraints(Certificate certificate) {
        if (certificate == null || certificate.getExtensions() == null) {
            return Optional.empty();
        }

        return certificate.getExtensions().stream()
                .filter(ext -> ext.getExtensionType() == ExtensionType.BASIC_CONSTRAINTS)
                .findFirst();
    }

}
