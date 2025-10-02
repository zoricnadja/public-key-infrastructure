package com.example.publickeyinfrastructure.util;

import com.example.publickeyinfrastructure.model.CertificateExtension;
import com.example.publickeyinfrastructure.model.ExtensionType;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

public class ExtensionUtil {

    private final PublicKey issuerKey;
    private final PublicKey subjectKey;
    private final JcaX509ExtensionUtils extUtils;

    public ExtensionUtil(PublicKey issuerKey, PublicKey subjectKey) throws Exception {
        this.issuerKey = issuerKey;
        this.subjectKey = subjectKey;
        this.extUtils = new JcaX509ExtensionUtils();
    }

    public void addExtension(X509v3CertificateBuilder certBuilder, String oid, boolean critical, String value) throws Exception {
        ASN1ObjectIdentifier oidObj = new ASN1ObjectIdentifier(oid);
        ASN1Encodable extensionValue = buildExtensionValue(oid, value);
        if (extensionValue != null) {
            certBuilder.addExtension(oidObj, critical, extensionValue);
        }
    }

    private ASN1Encodable buildExtensionValue(String oid, String value) {
        // --- Basic Constraints ---
        if (oid.equals(Extension.basicConstraints.getId())) {
            // frontend: "CA=true,pathLen=0" or "CA=false"
            boolean isCA = value.contains("CA=true");
            Integer pathLen = null;
            if (value.contains("pathLen=")) {
                String[] parts = value.split("pathLen=");
                pathLen = Integer.parseInt(parts[1].trim());
            }
            return (pathLen != null) ? new BasicConstraints(pathLen) : new BasicConstraints(isCA);
        }

        // --- Key Usage ---
        if (oid.equals(Extension.keyUsage.getId())) {
            // frontend: "digitalSignature,keyEncipherment"
            String[] usages = value.split(",");
            int usageBits = 0;
            for (String u : usages) {
                switch (u.trim()) {
                    case "digitalSignature": usageBits |= KeyUsage.digitalSignature; break;
                    case "nonRepudiation": usageBits |= KeyUsage.nonRepudiation; break;
                    case "keyEncipherment": usageBits |= KeyUsage.keyEncipherment; break;
                    case "dataEncipherment": usageBits |= KeyUsage.dataEncipherment; break;
                    case "keyAgreement": usageBits |= KeyUsage.keyAgreement; break;
                    case "keyCertSign": usageBits |= KeyUsage.keyCertSign; break;
                    case "cRLSign": usageBits |= KeyUsage.cRLSign; break;
                    case "encipherOnly": usageBits |= KeyUsage.encipherOnly; break;
                    case "decipherOnly": usageBits |= KeyUsage.decipherOnly; break;
                }
            }
            return new KeyUsage(usageBits);
        }

        // --- Extended Key Usage ---
        if (oid.equals(Extension.extendedKeyUsage.getId())) {
            // frontend: "serverAuth,clientAuth"
            String[] usages = value.split(",");
            List<KeyPurposeId> purposeIds = new ArrayList<>();
            for (String u : usages) {
                switch (u.trim()) {
                    case "serverAuth": purposeIds.add(KeyPurposeId.id_kp_serverAuth); break;
                    case "clientAuth": purposeIds.add(KeyPurposeId.id_kp_clientAuth); break;
                    case "codeSigning": purposeIds.add(KeyPurposeId.id_kp_codeSigning); break;
                    case "emailProtection": purposeIds.add(KeyPurposeId.id_kp_emailProtection); break;
                    case "timeStamping": purposeIds.add(KeyPurposeId.id_kp_timeStamping); break;
                    case "OCSPSigning": purposeIds.add(KeyPurposeId.id_kp_OCSPSigning); break;
                }
            }
            return new ExtendedKeyUsage(purposeIds.toArray(new KeyPurposeId[0]));
        }

        // --- Subject Alternative Name ---
        if (oid.equals(Extension.subjectAlternativeName.getId())) {
            // frontend: "DNS=example.com,IP=127.0.0.1,email=test@example.com,URI=https://example.com"
            String[] parts = value.split(",");
            List<GeneralName> names = new ArrayList<>();
            for (String p : parts) {
                String[] kv = p.split("=", 2);
                if (kv.length < 2) continue;
                String type = kv[0].trim();
                String val = kv[1].trim();

                switch (type) {
                    case "DNS": names.add(new GeneralName(GeneralName.dNSName, val)); break;
                    case "IP": names.add(new GeneralName(GeneralName.iPAddress, val)); break;
                    case "email": names.add(new GeneralName(GeneralName.rfc822Name, val)); break;
                    case "URI": names.add(new GeneralName(GeneralName.uniformResourceIdentifier, val)); break;
                }
            }
            return new GeneralNames(names.toArray(new GeneralName[0]));
        }

        // --- Authority Key Identifier ---
        if (oid.equals(Extension.authorityKeyIdentifier.getId())) {
            return extUtils.createAuthorityKeyIdentifier(issuerKey);
        }

        // --- Subject Key Identifier ---
        if (oid.equals(Extension.subjectKeyIdentifier.getId())) {
            return extUtils.createSubjectKeyIdentifier(subjectKey);
        }

        // --- CRL Distribution Points ---
        if (oid.equals(Extension.cRLDistributionPoints.getId())) {
            // frontend: "http://example.com/crl.pem"
            DistributionPointName dpn = new DistributionPointName(
                    new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, value))
            );
            DistributionPoint distPoint = new DistributionPoint(dpn, null, null);
            return new CRLDistPoint(new DistributionPoint[] { distPoint });
        }

        return null;
    }

    public List<CertificateExtension> extractExtensions(JcaX509CertificateHolder certHolder) {
        List<CertificateExtension> extensionList = new ArrayList<>();
        try {
            Extensions extensions = certHolder.getExtensions();
            if (extensions == null) return extensionList;

            for (ASN1ObjectIdentifier oid : extensions.getExtensionOIDs()) {
                Extension ext = extensions.getExtension(oid);
                extensionList.add(new CertificateExtension(null, ext.isCritical(), ext.getExtnValue().toString(), ExtensionType.fromOid(String.valueOf(ext.getExtnId()))));
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to extract extensions", e);
        }
        return extensionList;
    }

    private String decodeExtensionValue(Extension extension) {
        try {
            ASN1Primitive derObject = ASN1Primitive.fromByteArray(extension.getExtnValue().getOctets());
            return derObject.toString();
        } catch (Exception e) {
            return "Failed to decode extension";
        }
    }
}
