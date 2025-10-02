package com.example.publickeyinfrastructure.keystore;

import com.example.publickeyinfrastructure.config.SecurityProperties;
import com.example.publickeyinfrastructure.model.CertificateEntity;
import com.example.publickeyinfrastructure.model.Certificate;
import com.example.publickeyinfrastructure.model.CertificateType;
import com.example.publickeyinfrastructure.model.Role;
import com.example.publickeyinfrastructure.model.User;
import com.example.publickeyinfrastructure.util.ExtensionUtil;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

@Component
public class ProjectKeyStore {

    private static final Logger logger = LoggerFactory.getLogger(ProjectKeyStore.class);

    private final KeyStore keyStore;
    private final SecurityProperties securityProperties;
    private final OrganizationKeyStore organizationKeyStore;


    // Index for fast lookup
    private final Map<String, List<String>> typeIndex = new HashMap<>();

    public ProjectKeyStore(SecurityProperties securityProperties, OrganizationKeyStore organizationKeyStore) {
        this.securityProperties = securityProperties;
        this.organizationKeyStore = organizationKeyStore;
        try {
            this.keyStore = KeyStore.getInstance("PKCS12");
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Failed to initialize KeyStore", e);
        }
    }

    public void loadOrCreate(String keystorePath) {
        File keystoreFile = new File(keystorePath);
        try {
            if (keystoreFile.exists()) {
                try (FileInputStream fis = new FileInputStream(keystoreFile)) {
                    keyStore.load(fis, getKeystorePassword());
                    logger.info("Loaded existing keystore from {}", keystorePath);
                }
            } else {
                keyStore.load(null, getKeystorePassword());
                File parentDir = keystoreFile.getParentFile();
                if (parentDir != null && !parentDir.exists()) {
                    parentDir.mkdirs();
                }
                logger.info("Initialized new empty keystore");
            }
            buildTypeIndex();
        } catch (Exception e) {
            logger.error("Failed to load or create keystore from {}", keystorePath, e);
            throw new RuntimeException("Failed to load or create keystore", e);
        }
    }

    private void buildTypeIndex() throws KeyStoreException {
        typeIndex.clear();
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            String type = extractTypeFromAlias(alias);
            if (type != null) {
                typeIndex.computeIfAbsent(type.toLowerCase(), k -> new ArrayList<>()).add(alias);
            }
        }
    }

    private String extractTypeFromAlias(String alias) {
        if (alias.contains("-")) {
            return alias.split("-", 2)[0];
        }
        return null;
    }

    public Map<CertificateType, List<X509Certificate>> getCACertificates() {
        Map<CertificateType, List<X509Certificate>> result = new HashMap<>();
        try {
            List<String> rootAliases = typeIndex.getOrDefault("root", List.of());
            List<String> intermediateAliases = typeIndex.getOrDefault("intermediate", List.of());
            for (String alias : rootAliases) {
                java.security.cert.Certificate cert = keyStore.getCertificate(alias);
                //todo add withdrawal logic
                if (cert instanceof X509Certificate x509Cert) {
                    result.computeIfAbsent(CertificateType.ROOT, k -> new ArrayList<>()).add(x509Cert);

                }
            }

            for (String alias : intermediateAliases) {
                java.security.cert.Certificate cert = keyStore.getCertificate(alias);
                if (cert instanceof X509Certificate x509Cert) {
                    result.computeIfAbsent(CertificateType.INTERMEDIATE, k -> new ArrayList<>()).add(x509Cert);
                }
            }
        } catch (KeyStoreException e) {
            logger.error("Failed to retrieve certificates", e);
        }
        return result;
    }

    public void save(String filePath) {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            keyStore.store(fos, getKeystorePassword());
            logger.info("Keystore saved successfully to {}", filePath);
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
            logger.error("Failed to save keystore to {}", filePath, e);
            throw new RuntimeException("Failed to save keystore", e);
        }
    }

    public void writeKeyEntry(String type, String serialNumber, PrivateKey key, X509Certificate certificate, String orgId) {
        try {
            if (type == null || serialNumber == null || type.isEmpty() || serialNumber.isEmpty()) {
                throw new IllegalArgumentException("Type and serial number cannot be null or empty");
            }
            if (orgId == null || orgId.isEmpty()) {
                throw new IllegalArgumentException("Organization ID cannot be null or empty");
            }

            String alias = type.toLowerCase() + "-" + serialNumber;
            organizationKeyStore.storeOrganizationKey(orgId, alias, key);

            keyStore.setCertificateEntry(alias, certificate);

            logger.debug("Certificate entry '{}' written successfully for organization '{}'", alias, orgId);

            typeIndex.computeIfAbsent(type.toLowerCase(), k -> new ArrayList<>()).add(alias);

        } catch (Exception e) {
            logger.error("Failed to write certificate entry", e);
            throw new RuntimeException("Failed to write certificate entry", e);
        }
    }

    public Optional<X509Certificate> readCertificateBySerialNumber(String serialNumber) {
        try {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (alias.endsWith("-" + serialNumber)) {
                    java.security.cert.Certificate cert = keyStore.getCertificate(alias);
                    if (cert instanceof X509Certificate x509Cert) {
                        return Optional.of(x509Cert);
                    }
                }
            }
        } catch (KeyStoreException e) {
            logger.error("Failed to read certificate by serialNumber '{}'", serialNumber, e);
        }
        return Optional.empty();
    }

    public List<X509Certificate> findAllByUser(User user) {
        try {
            List<X509Certificate> certificates = new ArrayList<>();
            List<String> serialNumbers = user.getCertificateSerialNumbers();
            Enumeration<String> aliases = keyStore.aliases();
            logger.debug(serialNumbers.toString());
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (serialNumbers.contains(alias.split("-")[1]) ||  user.getRole().equals(Role.ADMIN)){
                    java.security.cert.Certificate cert = keyStore.getCertificate(alias);
                    if (cert instanceof X509Certificate x509Cert) {
                        certificates.add(x509Cert);
                    }
                } //todo add for ca and user
            }
            return certificates;
        } catch (KeyStoreException e) {
            logger.error("Failed to read certificate by serialNumber", e);
        }
        return null;
    }


    public List<X509Certificate> findUnassignedCACertificates(List<String> serialNumbers) throws KeyStoreException {
        List<X509Certificate> result = new ArrayList<>();
        List<String> intermediateAliases = typeIndex.getOrDefault("intermediate", List.of());

        for (String alias : intermediateAliases) {
            if (!serialNumbers.contains(alias.split("-")[1])) {
                java.security.cert.Certificate cert = keyStore.getCertificate(alias);
                if (cert instanceof X509Certificate x509Cert) {
                    result.add(x509Cert);
                }
            }
        }
        return result;
    }

    public Optional<X509Certificate> readCertificate(String type, String serialNumber) {
        String alias = type.toLowerCase() + "-" + serialNumber;
        try {
            java.security.cert.Certificate cert = keyStore.getCertificate(alias);
            return cert != null ? Optional.of((X509Certificate) cert) : Optional.empty();
        } catch (KeyStoreException e) {
            logger.error("Failed to read certificate '{}'", alias, e);
            return Optional.empty();
        }
    }

    public Optional<PrivateKey> readPrivateKey(String orgId, String type, String serialNumber) {
        String alias = type.toLowerCase() + "-" + serialNumber;
        try {
            if (!keyStore.containsAlias(alias)) {
                logger.error("Alias '{}' not found", alias);
                return Optional.empty();
            }

            PrivateKey key = organizationKeyStore.loadOrganizationKey(orgId, alias);
            return Optional.ofNullable(key);

        } catch (Exception e) {
            logger.error("Failed to read private key for alias '{}'", alias, e);
            return Optional.empty();
        }
    }

    public Optional<CertificateEntity> readCertificateEntity(String orgId, String type, String serialNumber) {
        try {
            Optional<X509Certificate> certOpt = readCertificate(type, serialNumber);
            Optional<PrivateKey> keyOpt = readPrivateKey(orgId, type, serialNumber);

            if (certOpt.isEmpty() || keyOpt.isEmpty()) {
                return Optional.empty();
            }

            X509Certificate cert = certOpt.get();
            PrivateKey key = keyOpt.get();

            X500Name subjectName = new JcaX509CertificateHolder(cert).getSubject();
            CertificateEntity entity = new CertificateEntity();
            entity.setPrivateKey(key);

            entity.setCommonName(getRDN(subjectName, BCStyle.CN));
            entity.setOrganization(getRDN(subjectName, BCStyle.O));
            entity.setOrganizationalUnit(getRDN(subjectName, BCStyle.OU));
            entity.setCountry(getRDN(subjectName, BCStyle.C));
            entity.setState(getRDN(subjectName, BCStyle.ST));
            entity.setLocality(getRDN(subjectName, BCStyle.L));

            return Optional.of(entity);

        } catch (CertificateEncodingException e) {
            logger.error("Failed to extract certificate entity for alias '{}-{}'", type, serialNumber, e);
            return Optional.empty();
        }
    }

    public Optional<X509Certificate> readCertificateBySubjectDN(String subjectDN) {
        try {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                java.security.cert.Certificate cert = keyStore.getCertificate(alias);

                if (cert instanceof X509Certificate x509Cert) {
                    String certSubject = x509Cert.getSubjectX500Principal().getName();

                    if (certSubject.equals(subjectDN)) {
                        Certificate domainCert = convertX509ToCertificate(x509Cert);

                        if (Boolean.TRUE.equals(domainCert.getIsWithdrawn())) {
                            logger.warn("Certificate with subjectDN={} found but is withdrawn (alias={})", subjectDN, alias);
                            continue; // skip withdrawn certs
                        }

                        logger.debug("Found valid certificate for subjectDN={} under alias={}", subjectDN, alias);
                        return Optional.of(x509Cert);
                    }
                }
            }
        } catch (Exception e) {
            logger.error("Failed to read certificate by Subject DN '{}'", subjectDN, e);
        }
        return Optional.empty();
    }




    public Certificate convertX509ToCertificate(X509Certificate x509Cert) throws Exception {
        Certificate certificate = new Certificate();

        JcaX509CertificateHolder certHolder = new JcaX509CertificateHolder(x509Cert);
        X500Name subjectName = certHolder.getSubject();
        X500Name issuerName = certHolder.getIssuer();
        CertificateEntity subjectEntity = new CertificateEntity();
        subjectEntity.setCommonName(getRDN(subjectName, BCStyle.CN));
        subjectEntity.setOrganization(getRDN(subjectName, BCStyle.O));
        subjectEntity.setOrganizationalUnit(getRDN(subjectName, BCStyle.OU));
        subjectEntity.setCountry(getRDN(subjectName, BCStyle.C));
        subjectEntity.setEmail(getRDN(subjectName, BCStyle.E));
        subjectEntity.setState(getRDN(subjectName, BCStyle.ST));
        subjectEntity.setLocality(getRDN(subjectName, BCStyle.L));
        subjectEntity.setPublicKey(x509Cert.getPublicKey());

        CertificateEntity issuerEntity = new CertificateEntity();
        issuerEntity.setCommonName(getRDN(issuerName, BCStyle.CN));
        issuerEntity.setOrganization(getRDN(issuerName, BCStyle.O));
        issuerEntity.setOrganizationalUnit(getRDN(issuerName, BCStyle.OU));
        issuerEntity.setCountry(getRDN(issuerName, BCStyle.C));
        issuerEntity.setEmail(getRDN(issuerName, BCStyle.E));
        issuerEntity.setState(getRDN(issuerName, BCStyle.ST));
        issuerEntity.setLocality(getRDN(issuerName, BCStyle.L));
        issuerEntity.setPublicKey(null);//  must load separately

        certificate.setSubject(subjectEntity);
        certificate.setIssuer(issuerEntity);
        certificate.setSerialNumber(x509Cert.getSerialNumber().toString(16));
        certificate.setIssued(x509Cert.getNotBefore());
        certificate.setExpires(x509Cert.getNotAfter());
        certificate.setSignatureAlgorithm(x509Cert.getSigAlgName());
        certificate.setSignature(x509Cert.getSignature());
        certificate.setVersion(x509Cert.getVersion());
        // Extensions — možeš dodati ako želiš
        certificate.setExtensions(new ExtensionUtil(issuerEntity.getPublicKey(), subjectEntity.getPublicKey())
                .extractExtensions(certHolder));

        return certificate;
    }

    private String getRDN(X500Name name, ASN1ObjectIdentifier oid) {
        RDN[] rdns = name.getRDNs(oid);
        if (rdns.length > 0) {
            return IETFUtils.valueToString(rdns[0].getFirst().getValue());
        }
        return null;
    }

    public void exportCertificate(X509Certificate cert, String fileName) {
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            fos.write(cert.getEncoded());
            logger.info("Certificate exported to {}", fileName);
        } catch (IOException | CertificateEncodingException e) {
            logger.error("Failed to export certificate to {}", fileName, e);
            throw new RuntimeException("Failed to export certificate", e);
        }
    }

    private char[] getKeystorePassword() {
        String password = securityProperties.getKeystore().getPassword();
        if (password == null || password.isEmpty()) {
            throw new IllegalStateException("Keystore password is not set");
        }
        return password.toCharArray();
    }

}
