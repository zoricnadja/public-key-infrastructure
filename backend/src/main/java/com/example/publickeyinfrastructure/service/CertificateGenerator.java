package com.example.publickeyinfrastructure.service;

import com.example.publickeyinfrastructure.config.Constants;
import com.example.publickeyinfrastructure.model.Certificate;
import com.example.publickeyinfrastructure.model.CertificateType;
import com.example.publickeyinfrastructure.model.CertificateEntity;
import com.example.publickeyinfrastructure.util.DateUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;

public class CertificateGenerator {
    private static final Logger logger = LoggerFactory.getLogger(CertificateGenerator.class);

    /**
     * Univerzalna metoda za kreiranje sertifikata na osnovu prosledjenih podataka
     */
    public static X509Certificate generateCertificate(Certificate certificateData,
                                                      X509Certificate issuerCert,
                                                      PrivateKey issuerPrivateKey) throws Exception {

        X500Name subjectName = certificateData.getSubject().getX500Name();

        X500Name issuerName;
        if (certificateData.getType() == CertificateType.ROOT) {
            issuerName = subjectName;
        } else {
            issuerName = certificateData.getIssuer().getX500Name();
        }

//        KeyPair keyPair = generateKey();

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerName,
                new BigInteger(64, new SecureRandom()),
                certificateData.getIssued(),
                certificateData.getExpires(),
                subjectName,
                certificateData.getSubject().getPublicKey()
        );

        addExtensions(certBuilder, certificateData.getType(), certificateData.getSubject().getPublicKey(), issuerCert);

        ContentSigner signer;
        PublicKey verificationKey;

        if (certificateData.getType() == CertificateType.ROOT) {
            signer = new JcaContentSignerBuilder(Constants.SIGNATURE_ALGORITHM)
                    .build(certificateData.getSubject().getPrivateKey());
            verificationKey = certificateData.getSubject().getPublicKey();
        } else {
            signer = new JcaContentSignerBuilder(Constants.SIGNATURE_ALGORITHM)
                    .build(issuerPrivateKey);
            verificationKey = issuerCert.getPublicKey();
        }

        X509CertificateHolder holder = certBuilder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider(Constants.PROVIDER)
                .getCertificate(holder);

        cert.verify(verificationKey);

        return cert;
    }

    /**
     * Convenience metoda za kreiranje Root CA sertifikata
     */
    public static X509Certificate generateRootCA(Certificate certificateData) throws Exception {
        certificateData.setType(CertificateType.ROOT);
        return generateCertificate(certificateData, null, null);
    }

    /**
     * Convenience metoda za kreiranje Intermediate CA sertifikata
     */
    public static X509Certificate generateIntermediateCA(Certificate certificateData,
                                                         X509Certificate issuerCert,
                                                         PrivateKey issuerPrivateKey) throws Exception {
        certificateData.setType(CertificateType.INTERMEDIATE);
        return generateCertificate(certificateData, issuerCert, issuerPrivateKey);
    }

    /**
     * Convenience metoda za kreiranje End Entity sertifikata
     */
    public static X509Certificate generateEndEntity(Certificate certificateData,
                                                    X509Certificate issuerCert,
                                                    PrivateKey issuerPrivateKey) throws Exception {
        certificateData.setType(CertificateType.END_ENTITY);
        return generateCertificate(certificateData, issuerCert, issuerPrivateKey);
    }


    /**
     * Dodaje potrebne ekstenzije na osnovu tipa sertifikata
     */
    private static void addExtensions(JcaX509v3CertificateBuilder certBuilder,
                                      CertificateType type,
                                      PublicKey subjectPublicKey,
                                      X509Certificate issuerCert) throws Exception {

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        switch (type) {
            case ROOT:
                certBuilder.addExtension(Extension.keyUsage, true,
                        new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

                certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                        extUtils.createSubjectKeyIdentifier(subjectPublicKey));
                //                certBuilder.addExtension(Extension.basicConstraints, true,
//                       new BasicConstraints(Integer.MAX_VALUE));
                break;

            case INTERMEDIATE:
//                certBuilder.addExtension(Extension.basicConstraints, true,
//                        new BasicConstraints(Integer.MAX_VALUE));

                certBuilder.addExtension(Extension.keyUsage, true,
                        new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

                certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                        extUtils.createSubjectKeyIdentifier(subjectPublicKey));

                if (issuerCert != null) {
                    certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                            extUtils.createAuthorityKeyIdentifier(issuerCert));
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

                if (issuerCert != null) {
                    certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                            extUtils.createAuthorityKeyIdentifier(issuerCert));
                }

                GeneralNames subjectAltNames = new GeneralNames(
                        new GeneralName(GeneralName.dNSName, "localhost")
                );
                certBuilder.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
                break;
        }
    }


    /**
     * Helper metoda za kreiranje Certificate objekta sa osnovnim podacima
     */
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