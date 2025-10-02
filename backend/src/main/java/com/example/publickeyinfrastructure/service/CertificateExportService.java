package com.example.publickeyinfrastructure.service;

import com.example.publickeyinfrastructure.keystore.ProjectKeyStore;
import com.example.publickeyinfrastructure.mapper.CertificateMapper;
import com.example.publickeyinfrastructure.model.CertificateType;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.UUID;

@Service
public class CertificateExportService {

    private static final Logger logger = LoggerFactory.getLogger(CertificateExportService.class);

    private final ProjectKeyStore projectKeyStore;
    private final CertificateMapper certificateMapper;
    @Value("${keystore.path}")
    private String keyStorePath;

    public CertificateExportService(ProjectKeyStore projectKeyStore, CertificateMapper certificateMapper) {
        this.projectKeyStore = projectKeyStore;
        this.certificateMapper = certificateMapper;
    }

    public byte[] createKeystoreWithKey(String serialNumber) throws Exception {
        projectKeyStore.loadOrCreate(this.keyStorePath);

        var certOpt = projectKeyStore.readCertificateBySerialNumber(serialNumber);
        if (certOpt.isEmpty()) {
            throw new IllegalArgumentException("Certificate not found");
        }
        X509Certificate cert = certOpt.get();

        String orgId = new JcaX509CertificateHolder(cert).getSubject()
                .getRDNs(BCStyle.O)[0].getFirst().getValue().toString();

        CertificateType type = null;
        for (CertificateType t : CertificateType.values()) {
            if (projectKeyStore.readCertificate(t.name().toLowerCase(), serialNumber).isPresent()) {
                type = t;
                break;
            }
        }
        if (type == null) {
            throw new IllegalStateException("Certificate type not found");
        }

        PrivateKey privateKey = projectKeyStore
                .readPrivateKey(orgId, type.name().toLowerCase(), serialNumber)
                .orElseThrow(() -> new IllegalArgumentException("Private key not found"));

        String passwordStr = UUID.randomUUID().toString().replace("-", "");
        char[] password = passwordStr.toCharArray();

        KeyStore jks = KeyStore.getInstance("JKS");
        jks.load(null, password);

        String alias = type.name().toLowerCase() + "-" + serialNumber;
        jks.setKeyEntry(alias, privateKey, password, new X509Certificate[]{cert});
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        jks.store(baos, password);

        return baos.toByteArray();
    }
}
