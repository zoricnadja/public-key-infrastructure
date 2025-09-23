package com.example.publickeyinfrastructure.keystore;

import com.example.publickeyinfrastructure.model.Issuer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.springframework.stereotype.Component;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

@Component
public class ProjectKeyStore {

    private KeyStore keyStore;

    public ProjectKeyStore() {
        try {
            keyStore = KeyStore.getInstance("JKS");
        } catch (KeyStoreException e) {
            throw new RuntimeException("Failed to initialize KeyStore", e);
        }
    }

    public void load(String filePath, char[] password) {
        try (FileInputStream fis = filePath != null ? new FileInputStream(filePath) : null) {
            keyStore.load(fis, password);
        } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to load KeyStore", e);
        }
    }

    public void save(String filePath, char[] password) {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            keyStore.store(fos, password);
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
            throw new RuntimeException("Failed to save KeyStore", e);
        }
    }

    public void writeKeyEntry(String alias, PrivateKey key, char[] keyPassword, X509Certificate certificate) {
        try {
            keyStore.setKeyEntry(alias, key, keyPassword, new java.security.cert.Certificate[]{certificate});
        } catch (KeyStoreException e) {
            throw new RuntimeException("Failed to write key entry", e);
        }
    }

    public X509Certificate readCertificate(String alias) {
        try {
            java.security.cert.Certificate cert = keyStore.getCertificate(alias);
            return cert != null ? (X509Certificate) cert : null;
        } catch (KeyStoreException e) {
            throw new RuntimeException("Failed to read certificate", e);
        }
    }

    public PrivateKey readPrivateKey(String alias, char[] keyPassword) {
        try {
            return (PrivateKey) keyStore.getKey(alias, keyPassword);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new RuntimeException("Failed to read private key", e);
        }
    }

    public Issuer readIssuer(String alias, char[] keyPassword) {
        X509Certificate cert = readCertificate(alias);
        PrivateKey key = readPrivateKey(alias, keyPassword);
        try {
            X500Name x500 = new JcaX509CertificateHolder(cert).getSubject();
            Issuer issuer = new Issuer();
            issuer.setPrivateKey(key);

            X500Name issuerName = new JcaX509CertificateHolder((X509Certificate) cert).getSubject();
            issuer.setCommonName(getRDN(issuerName, BCStyle.CN));
            issuer.setOrganization(getRDN(issuerName, BCStyle.O));
            issuer.setOrganizationalUnit(getRDN(issuerName, BCStyle.OU));
            issuer.setCountry(getRDN(issuerName, BCStyle.C));
            issuer.setState(getRDN(issuerName, BCStyle.ST));
            issuer.setLocality(getRDN(issuerName, BCStyle.L));
            return issuer;
        } catch (CertificateEncodingException e) {
            throw new RuntimeException("Failed to extract issuer info", e);
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
        } catch (IOException | CertificateEncodingException e) {
            throw new RuntimeException("Failed to export certificate", e);
        }
    }
}

