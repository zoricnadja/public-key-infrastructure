package com.example.publickeyinfrastructure.mapper;

import com.example.publickeyinfrastructure.config.Constants;
import com.example.publickeyinfrastructure.dto.CertificateResponse;
import com.example.publickeyinfrastructure.dto.CreateCertificateRequest;
import com.example.publickeyinfrastructure.model.Certificate;
import com.example.publickeyinfrastructure.model.CertificateEntity;
import com.example.publickeyinfrastructure.model.CertificateType;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.StringReader;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

@Component
public class CertificateMapper {

    private final ModelMapper mapper;
    private final ExtensionMapper extensionMapper;
    private final X500NameMapper x500NameMapper;

    @Autowired
    public CertificateMapper(ModelMapper mapper, ExtensionMapper extensionMapper, X500NameMapper x500NameMapper) {
        this.mapper = mapper;
        this.extensionMapper = extensionMapper;
        this.x500NameMapper = x500NameMapper;
    }

    public CertificateResponse toDto(Certificate certificate) {

        CertificateResponse response = mapper.map(certificate, CertificateResponse.class);

        if (certificate.getSubject() != null) {
            response.setSubjectCN(certificate.getSubject().getCommonName());
            response.setSubjectO(certificate.getSubject().getOrganization());
            response.setSubjectOU(certificate.getSubject().getOrganizationalUnit());
        }

        if (certificate.getIssuer() != null) {
            response.setIssuerCN(certificate.getIssuer().getCommonName());
            response.setIssuerO(certificate.getIssuer().getOrganization());
            response.setIssuerOU(certificate.getIssuer().getOrganizationalUnit());
        }

        return response;
    }

    public CertificateResponse toDto(CertificateType type, X509Certificate certificate) {

        CertificateResponse response = this.toDto(certificate);
        response.setType(type);
        return response;
    }

    public CertificateResponse toDto(X509Certificate cert) {
        CertificateResponse response = new CertificateResponse();
        try {
            JcaX509CertificateHolder holder = new JcaX509CertificateHolder(cert);
            X500Name subjectName = holder.getSubject();
            X500Name issuerName = holder.getIssuer();

            response.setSerialNumber(cert.getSerialNumber().toString());
            response.setIssued(cert.getNotBefore());
            response.setExpires(cert.getNotAfter());
            response.setSignatureAlgorithm(cert.getSigAlgName());

            response.setSubjectCN(getRDN(subjectName, BCStyle.CN));
            response.setSubjectO(getRDN(subjectName, BCStyle.O));
            response.setSubjectOU(getRDN(subjectName, BCStyle.OU));

            response.setIssuerCN(getRDN(issuerName, BCStyle.CN));
            response.setIssuerO(getRDN(issuerName, BCStyle.O));
            response.setIssuerOU(getRDN(issuerName, BCStyle.OU));

        } catch (Exception e) {
            throw new RuntimeException("Failed to map X509Certificate to CertificateResponse", e);
        }
        return response;
    }

    private String getRDN(X500Name name, ASN1ObjectIdentifier oid) {
        RDN[] rdns = name.getRDNs(oid);
        if (rdns.length > 0) {
            return IETFUtils.valueToString(rdns[0].getFirst().getValue());
        }
        return null;
    }

    public Certificate toEntity(CreateCertificateRequest request) {
        Certificate certificate = mapper.map(request, Certificate.class);

        if (request.getCsrPem() != null && !request.getCsrPem().isBlank()) {
            try (PEMParser pemParser = new PEMParser(new StringReader(request.getCsrPem()))) {
                Object obj = pemParser.readObject();
                if (!(obj instanceof PKCS10CertificationRequest csr)) {
                    throw new IllegalArgumentException("Invalid CSR provided");
                }

                X500Name subject = csr.getSubject();
                PublicKey publicKey = new JcaPEMKeyConverter()
                        .setProvider(Constants.PROVIDER)
                        .getPublicKey(csr.getSubjectPublicKeyInfo());
                CertificateEntity subjectEntity = x500NameMapper.toEntity(subject);
                subjectEntity.setPublicKey(publicKey);

                certificate.setSubject(subjectEntity);
                //todo extensions
            } catch (Exception e) {
                throw new RuntimeException("Failed to parse CSR", e);
            }
        }else{
            certificate.setSubject(x500NameMapper.toEntity(request.getSubject()));
            certificate.setExtensions(request.getExtensions().stream().map(extensionMapper::toEntity).toList());
        }
        return certificate;
    }
}