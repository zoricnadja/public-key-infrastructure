package com.example.publickeyinfrastructure.service;

import com.example.publickeyinfrastructure.config.Constants;
import com.example.publickeyinfrastructure.keystore.ProjectKeyStore;
import com.example.publickeyinfrastructure.model.Certificate;
import com.example.publickeyinfrastructure.model.CertificateType;
import com.example.publickeyinfrastructure.model.CertificateEntity;
import com.example.publickeyinfrastructure.model.Role;
import com.example.publickeyinfrastructure.model.User;
import com.example.publickeyinfrastructure.repository.CertificateRepository;
import com.example.publickeyinfrastructure.repository.RevokedCertificateRepository;
import jakarta.persistence.EntityNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class CertificateService {

    @Value("${keystore.path}")
    private String keystorePath;
    private final CertificateRepository certificateRepository;
    private final RevokedCertificateRepository revokedCertificateRepository;

    private static final Logger logger = LoggerFactory.getLogger(CertificateService.class);

    private final ProjectKeyStore projectKeyStore;

    @Autowired
    public CertificateService(CertificateRepository certificateRepository, ProjectKeyStore projectKeyStore, RevokedCertificateRepository revokedCertificateRepository) {
        this.certificateRepository = certificateRepository;
        this.projectKeyStore = projectKeyStore;
        this.revokedCertificateRepository = revokedCertificateRepository;
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

    public Optional<X509Certificate> findBySerialNumber(String serialNumber){
        projectKeyStore.loadOrCreate(keystorePath);
        return projectKeyStore.readCertificateBySerialNumber(serialNumber);
    }

    public List<X509Certificate> findAllByUser(User user) {
        projectKeyStore.loadOrCreate(keystorePath);
        return projectKeyStore.findAllByUser(user);
    }

    public Map<CertificateType, List<X509Certificate>> findAllIssuers(){
        projectKeyStore.loadOrCreate(keystorePath);
        return projectKeyStore.getCACertificates();
    }

    public List<X509Certificate> findAllUnassignedCACertificates(List<String> serialNumbers) throws KeyStoreException {
        projectKeyStore.loadOrCreate(keystorePath);
        return projectKeyStore.findUnassignedCACertificates(serialNumbers);
    }

    public boolean isRevoked(X509Certificate certificate) {
        return revokedCertificateRepository.existsBySerialNumber(certificate.getSerialNumber().toString());
    }

    private void checkChain(X509Certificate certificate) throws Exception {
        X509Certificate currentCert = certificate;

        while (true) {
            currentCert.checkValidity();

            if (isSelfSigned(currentCert)) {
                currentCert.verify(currentCert.getPublicKey());
                break;
            }

            if (revokedCertificateRepository.existsBySerialNumber(currentCert.getSerialNumber().toString())) {
                throw new SecurityException("Certificate with serial number " + currentCert.getSerialNumber() + " is revoked.");
            }

            X509Certificate finalCurrentCert = currentCert;
            X509Certificate issuerCert = projectKeyStore.readCertificateBySubjectDN(
                    currentCert.getIssuerX500Principal().getName()
            ).orElseThrow(() -> new EntityNotFoundException(
                    "Issuer certificate not found for " + finalCurrentCert.getSerialNumber()
            ));
            currentCert.verify(issuerCert.getPublicKey());

            currentCert = issuerCert;
        }
    }

    private boolean isSelfSigned(X509Certificate cert) {
        try {
            return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())
                    && verifySelfSigned(cert);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean verifySelfSigned(X509Certificate cert) {
        try {
            cert.verify(cert.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public Certificate createCertificate(Certificate request, Role subjectRole, String issuerSerialNumber, CertificateType issuerCertificateType) throws Exception {
        CertificateEntity subject = request.getSubject();
        request.setSubject(subject);
        request.setSignatureAlgorithm(Constants.SIGNATURE_ALGORITHM);
        BigInteger serial = new BigInteger(128, new SecureRandom());
        request.setSerialNumber(serial.toString(16).toUpperCase());
        X509Certificate xCertificate;
        projectKeyStore.loadOrCreate(keystorePath);

        if(request.getType().equals(CertificateType.ROOT)) {
            if(subjectRole.equals(Role.ADMIN)) {
                createRootCertificateEntities(request);
                xCertificate = CertificateGenerator.generateX509Certificate(request, request.getSubject().getPrivateKey(), request.getSubject().getPublicKey());
            }
            else
                throw new IllegalArgumentException("You don't have permission to create Root CA Certificate");
        } else {
            X509Certificate issuerX509Certificate = projectKeyStore.readCertificateBySerialNumber(issuerSerialNumber).orElseThrow(() -> new EntityNotFoundException("Certificate not found"));
            Certificate issuerCertificate = projectKeyStore.convertX509ToCertificate(issuerX509Certificate);
            PrivateKey issuerPrivateKey = projectKeyStore.readPrivateKey(issuerCertificate.getSubject().getOrganization(), issuerCertificateType.name(), issuerSerialNumber).orElseThrow(() -> new EntityNotFoundException("Private key not found"));
            if(!request.isDateValid() || request.getExpires().after(issuerCertificate.getExpires()))
                throw new IllegalArgumentException("Subject's expiration date cannot be after issuer's expiration date");
            request.setIssuer(issuerCertificate.getSubject());
            KeyPair subjectKeyPair = this.generateKeyPair();
            request.getSubject().setPublicKey(subjectKeyPair.getPublic());
            request.getSubject().setPrivateKey(subjectKeyPair.getPrivate());
            if (request.getType().equals(CertificateType.INTERMEDIATE) && subjectRole.equals(Role.USER))
                throw new IllegalCallerException("You don't have permission for intermediate certificates");
            xCertificate = CertificateGenerator.generateX509Certificate(request, issuerPrivateKey, request.getIssuer().getPublicKey());
        }
        checkChain(xCertificate);
        request.setSignature(xCertificate.getSignature());
        request.setSerialNumber(xCertificate.getSerialNumber().toString());
        //todo only save to keystore
        request = certificateRepository.save(request);
        projectKeyStore.writeKeyEntry(request.getType().name(), String.format(request.getSerialNumber()), request.getSubject().getPrivateKey(), xCertificate, request.getSubject().getOrganization());
        projectKeyStore.save(keystorePath);
        return request;
    }

    private void createRootCertificateEntities(Certificate certificate){
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
    }
}
