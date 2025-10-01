package com.example.publickeyinfrastructure.service;

import com.example.publickeyinfrastructure.config.Constants;
import com.example.publickeyinfrastructure.model.Certificate;
import com.example.publickeyinfrastructure.model.CertificateExtension;
import com.example.publickeyinfrastructure.model.CertificateType;
import com.example.publickeyinfrastructure.model.CertificateEntity;
import com.example.publickeyinfrastructure.model.ExtensionType;
import com.example.publickeyinfrastructure.util.DateUtil;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;

public class CertificateGenerator {
    private static final Logger logger = LoggerFactory.getLogger(CertificateGenerator.class);

    public static X509Certificate generateX509Certificate(Certificate certificate,
                                                          PrivateKey issuerPrivateKey,
                                                          PublicKey issuerPublicKey) throws Exception {

        PublicKey verificationKey;
        if (certificate.getType() == CertificateType.ROOT) {
            verificationKey = certificate.getSubject().getPublicKey();
        } else {
            verificationKey = issuerPublicKey;
        }
        addBasicConstraints(certificate);
        X509Certificate cert = certificate.toX509Certificate(issuerPrivateKey);
        cert.verify(verificationKey);
        return cert;
    }

    private static void addBasicConstraints(Certificate certificate) throws IOException {
        BasicConstraints bc;
        switch (certificate.getType()) {
            case ROOT, INTERMEDIATE -> bc = new BasicConstraints(true);
            case END_ENTITY -> bc = new BasicConstraints(false);
            default -> throw new IllegalStateException("Unknown type: " + certificate.getType());
        }
        byte[] value = bc.getEncoded();
        certificate.addExtension(
                new CertificateExtension(null, true, bc.getEncoded(), ExtensionType.BASIC_CONSTRAINTS)
        );
    }

    //todo check extensions
    private void addExtensions(JcaX509v3CertificateBuilder certBuilder,
                                      CertificateType type,
                                      PublicKey subjectPublicKey,
                                      X509Certificate issuerCertificate) throws Exception {

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        switch (type) {
            case ROOT:
                certBuilder.addExtension(Extension.keyUsage, true,
                        new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

                certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                        extUtils.createSubjectKeyIdentifier(subjectPublicKey));
                break;

            case INTERMEDIATE:
//                certBuilder.addExtension(Extension.basicConstraints, true,
//                        new BasicConstraints(Integer.MAX_VALUE));

                certBuilder.addExtension(Extension.keyUsage, true,
                        new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

                certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                        extUtils.createSubjectKeyIdentifier(subjectPublicKey));

                if (issuerCertificate != null) {
                    certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                            extUtils.createAuthorityKeyIdentifier(issuerCertificate));
                }
                break;

            case END_ENTITY:
//                certBuilder.addExtension(Extension.basicConstraints, true,
//                        new BasicConstraints(false));

                certBuilder.addExtension(Extension.keyUsage, true,
                        new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

                certBuilder.addExtension(Extension.extendedKeyUsage, false,
                        new ExtendedKeyUsage(new KeyPurposeId[]{
                                KeyPurposeId.id_kp_serverAuth,
                                KeyPurposeId.id_kp_clientAuth
                        }));

                certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                        extUtils.createSubjectKeyIdentifier(subjectPublicKey));

                if (issuerCertificate != null) {
                    certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                            extUtils.createAuthorityKeyIdentifier(issuerCertificate));
                }

                GeneralNames subjectAltNames = new GeneralNames(
                        new GeneralName(GeneralName.dNSName, "localhost")
                );
                certBuilder.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
                break;
        }
    }


    public static Certificate createCertificateData(CertificateEntity subject, CertificateEntity issuer,
                                                    String serialNumber, CertificateType type) {
        Certificate cert = new Certificate();
        cert.setSubject(subject);
        cert.setIssuer(issuer);
        cert.setSerialNumber(serialNumber);
        cert.setType(type);
        cert.setIssued(DateUtil.generateStartTime());
        cert.setExpires(DateUtil.generateEndTime(cert.getIssued(), type));
        cert.setIsWithdrawn(false);
        cert.setVersion(3); // X.509 v3
        cert.setSignatureAlgorithm(Constants.SIGNATURE_ALGORITHM);

        return cert;
    }
}