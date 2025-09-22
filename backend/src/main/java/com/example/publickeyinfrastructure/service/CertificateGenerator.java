package com.example.publickeyinfrastructure.service;

import com.example.publickeyinfrastructure.configuration.Constants;
import com.example.publickeyinfrastructure.model.CertificateType;
import com.example.publickeyinfrastructure.util.DateUtil;
import org.bouncycastle.asn1.x500.X500Name;
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

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertificateGenerator {

    public static CertBundle generateRootCA(String dn, long serial) throws Exception {
        KeyPair keyPair = generateKeyPair();
        X500Name subject = new X500Name(dn);

        Date issued = DateUtil.generateStartTime();
        Date expires = DateUtil.generateEndTime(issued, CertificateType.ROOT);

        JcaX509v3CertificateBuilder certBuilder =
                new JcaX509v3CertificateBuilder(
                        subject,
                        BigInteger.valueOf(serial),
                        issued,
                        expires,
                        subject,
                        keyPair.getPublic()
                );

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(Integer.MAX_VALUE));
        certBuilder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));

        ContentSigner signer = new JcaContentSignerBuilder(Constants.SIGNATURE_ALGORITHM)
                .build(keyPair.getPrivate());

        X509CertificateHolder holder = certBuilder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(holder);

        cert.verify(keyPair.getPublic());

        return new CertBundle(cert, keyPair.getPrivate());
    }

    public static CertBundle generateSubCA(String dn, long serial,
                                           X509Certificate issuerCert, PrivateKey issuerKey) throws Exception {
        KeyPair keyPair = generateKeyPair();
        X500Name subject = new X500Name(dn);
        X500Name issuer = new X500Name(issuerCert.getSubjectX500Principal().getName());

        Date issued = DateUtil.generateStartTime();
        Date expires = DateUtil.generateEndTime(issued, CertificateType.INTERMEDIATE);

        JcaX509v3CertificateBuilder certBuilder =
                new JcaX509v3CertificateBuilder(
                        issuer,
                        BigInteger.valueOf(serial),
                        issued,
                        expires,
                        subject,
                        keyPair.getPublic()
                );

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(Integer.MAX_VALUE));
        certBuilder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(issuerCert));

        ContentSigner signer = new JcaContentSignerBuilder(Constants.SIGNATURE_ALGORITHM)
                .build(issuerKey);

        X509CertificateHolder holder = certBuilder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(holder);

        cert.verify(issuerCert.getPublicKey());

        return new CertBundle(cert, keyPair.getPrivate());
    }

    public static CertBundle generateLeafCert(String dn, long serial,
                                              X509Certificate issuerCert, PrivateKey issuerKey) throws Exception {
        KeyPair keyPair = generateKeyPair();
        X500Name subject = new X500Name(dn);
        X500Name issuer = new X500Name(issuerCert.getSubjectX500Principal().getName());

        Date issued = DateUtil.generateStartTime();
        Date expires = DateUtil.generateEndTime(issued, CertificateType.END_ENTITY);

        JcaX509v3CertificateBuilder certBuilder =
                new JcaX509v3CertificateBuilder(
                        issuer,
                        BigInteger.valueOf(serial),
                        issued,
                        expires,
                        subject,
                        keyPair.getPublic()
                );

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        certBuilder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        certBuilder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(new KeyPurposeId[]{
                        KeyPurposeId.id_kp_serverAuth,
                        KeyPurposeId.id_kp_clientAuth
                }));
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(issuerCert));
        ContentSigner signer = new JcaContentSignerBuilder(Constants.SIGNATURE_ALGORITHM)
                .build(issuerKey);
        GeneralNames subjectAltNames = new GeneralNames(
                new GeneralName(GeneralName.dNSName, "localhost")
        );
        certBuilder.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);

        X509CertificateHolder holder = certBuilder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(holder);

        cert.verify(issuerCert.getPublicKey());

        return new CertBundle(cert, keyPair.getPrivate());
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(Constants.KEY_SIZE);
        return keyGen.generateKeyPair();
    }

    public static record CertBundle(X509Certificate certificate, PrivateKey privateKey) {}
}
