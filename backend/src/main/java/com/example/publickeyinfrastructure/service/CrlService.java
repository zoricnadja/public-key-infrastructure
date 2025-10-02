package com.example.publickeyinfrastructure.service;

import com.example.publickeyinfrastructure.keystore.OrganizationKeyStore;
import com.example.publickeyinfrastructure.keystore.ProjectKeyStore;
import com.example.publickeyinfrastructure.model.RevokedCertificate;
import com.example.publickeyinfrastructure.repository.RevokedCertificateRepository;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

@Service
public class CrlService {
    private static final Logger logger = org.slf4j.LoggerFactory.getLogger(CrlService.class);

    private final RevokedCertificateRepository revokedCertificateRepository;
    private final ProjectKeyStore projectKeyStore;
    private final OrganizationKeyStore organizationKeyStore;

    @Autowired
    public CrlService(RevokedCertificateRepository revokedCertificateRepository, ProjectKeyStore projectKeyStore, OrganizationKeyStore organizationKeyStore) {
        this.revokedCertificateRepository = revokedCertificateRepository;
        this.projectKeyStore = projectKeyStore;
        this.organizationKeyStore = organizationKeyStore;
    }

    public byte[] generateCrlForIssuer(String issuerDn) throws Exception {
        X509Certificate caCert = projectKeyStore.readCertificateBySubjectDN(issuerDn).orElseThrow(() -> new Exception("CA Certificate not found for issuer: " + issuerDn));
        PrivateKey caKey = organizationKeyStore.loadOrganizationKey(getOrganization(caCert), caCert.getSerialNumber().toString());

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(
                new X500Name(caCert.getSubjectX500Principal().getName()), new Date());

        List<RevokedCertificate> revoked = revokedCertificateRepository.findAllByIssuerDn(issuerDn);
        for (RevokedCertificate rc : revoked) {
            crlBuilder.addCRLEntry(new BigInteger(rc.getSerialNumber()), rc.getRevokedAt(), rc.getReason().getCode());
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caKey);
        X509CRL crl = new JcaX509CRLConverter().getCRL(crlBuilder.build(signer));
        return crl.getEncoded();

//        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caKey);
//        X509CRLHolder crlHolder = crlBuilder.build(signer);
//
//        return crlHolder.getEncoded();
    }

    private String getOrganization(X509Certificate cert) {
        String dn = cert.getSubjectX500Principal().getName();
        try {
            LdapName ldapName = new LdapName(dn);
            for (Rdn rdn : ldapName.getRdns()) {
                if ("O".equalsIgnoreCase(rdn.getType())) {
                    return rdn.getValue().toString();
                }
            }
        } catch (Exception e) {
            logger.error("Failed to parse DN: {}", dn, e);
        }
        return null;
    }
}
