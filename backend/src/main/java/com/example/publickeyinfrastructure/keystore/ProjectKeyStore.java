package com.example.publickeyinfrastructure.keystore;

import com.example.publickeyinfrastructure.config.SecurityProperties;
import com.example.publickeyinfrastructure.model.CertificateEntity;
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
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Optional;

@Component
public class ProjectKeyStore {

    private static final Logger logger = LoggerFactory.getLogger(ProjectKeyStore.class);

    private final KeyStore keyStore;
    private final SecurityProperties securityProperties;


    public ProjectKeyStore(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
        try {
            this.keyStore = KeyStore.getInstance("JKS", "SUN");
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Failed to initialize KeyStore", e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
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
                // Initialize empty keystore
                keyStore.load(null, getKeystorePassword());

                // Create parent directories if needed
                File parentDir = keystoreFile.getParentFile();
                if (parentDir != null && !parentDir.exists()) {
                    parentDir.mkdirs();
                }

                logger.info("Initialized new empty keystore");
            }
        } catch (Exception e) {
            logger.error("Failed to load or create keystore from {}", keystorePath, e);
            throw new RuntimeException("Failed to load or create keystore", e);
        }
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

    public void writeKeyEntry(String alias, PrivateKey key, X509Certificate certificate) {
        try {
            if (alias == null || alias.isEmpty()) {
                throw new IllegalArgumentException("Alias cannot be null or empty");
            }
            keyStore.setKeyEntry(alias, key, getKeystorePassword(), new java.security.cert.Certificate[]{certificate});
            logger.info("Key entry '{}' written successfully", alias);
        } catch (KeyStoreException e) {
            logger.error("Failed to write key entry '{}'", alias, e);
            throw new RuntimeException("Failed to write key entry", e);
        }
    }

    public Optional<X509Certificate> readCertificate(String alias) {
        try {
            java.security.cert.Certificate cert = keyStore.getCertificate(alias);
            return cert != null ? Optional.of((X509Certificate) cert) : Optional.empty();
        } catch (KeyStoreException e) {
            logger.error("Failed to read certificate '{}'", alias, e);
            return Optional.empty();
        }
    }

    public Optional<PrivateKey> readPrivateKey(String alias) {
        try {
            Key key = keyStore.getKey(alias, getKeystorePassword());
            return Optional.ofNullable(key instanceof PrivateKey ? (PrivateKey) key : null);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            logger.error("Failed to read private key '{}'", alias, e);
            return Optional.empty();
        }
    }

    public Optional<X509Certificate> getCertificateBySerialNumber(String serialNumber) {
        try {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate cert = keyStore.getCertificate(alias);
                if (cert instanceof X509Certificate x509Cert) {
                    if (x509Cert.getSerialNumber().toString().equals(serialNumber)) {
                        return Optional.of(x509Cert);
                    }
                }
            }
        } catch (KeyStoreException e) {
            logger.error("Failed to search certificate by serial number '{}'", serialNumber, e);
        }
        return Optional.empty();
    }

    public Optional<CertificateEntity> readCertificateEntity(String alias) {
        try {
            Optional<X509Certificate> certOpt = readCertificate(alias);
            Optional<PrivateKey> keyOpt = readPrivateKey(alias);

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
            logger.error("Failed to extract certificate entity for alias '{}'", alias, e);
            return Optional.empty();
        }
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

    public boolean containsAlias(String alias) {
        try {
            return keyStore.containsAlias(alias);
        } catch (KeyStoreException e) {
            logger.error("Failed to check alias '{}'", alias, e);
            return false;
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
