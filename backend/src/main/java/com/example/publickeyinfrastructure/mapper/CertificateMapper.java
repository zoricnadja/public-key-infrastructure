package com.example.publickeyinfrastructure.mapper;

import com.example.publickeyinfrastructure.dto.CertificateDTO;
import com.example.publickeyinfrastructure.model.Certificate;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.modelmapper.Converter;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;

import java.io.StringWriter;
import java.security.cert.X509Certificate;

@Component
public class CertificateMapper {

    private final ModelMapper modelMapper;

    public CertificateMapper() {
        this.modelMapper = new ModelMapper();
        configureMapper();
    }

    private void configureMapper() {
        Converter<Certificate, String> certToPemConverter = context -> {
            Certificate cert = context.getSource();
            if (cert == null) return null;

            try {
                X509Certificate x509Cert = cert.toX509Certificate();
                StringWriter sw = new StringWriter();
                try (JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
                    pemWriter.writeObject(x509Cert);
                }
                return sw.toString();
            } catch (Exception e) {
                throw new RuntimeException("Failed to convert certificate to PEM", e);
            }
        };

        modelMapper.typeMap(Certificate.class, CertificateDTO.class)
                .addMappings(mapper -> mapper.using(certToPemConverter)
                        .map(src -> src, CertificateDTO::setCertificatePem))
                .addMapping(src -> src.getSubject() != null ? src.getSubject().getCommonName() : null,
                        CertificateDTO::setSubjectCN)
                .addMapping(src -> src.getSubject() != null ? src.getSubject().getOrganization() : null,
                        CertificateDTO::setSubjectO)
                .addMapping(src -> src.getSubject() != null ? src.getSubject().getOrganizationalUnit() : null,
                        CertificateDTO::setSubjectOU)
                .addMapping(src -> src.getIssuer() != null ? src.getIssuer().getCommonName() : null,
                        CertificateDTO::setIssuerCN)
                .addMapping(src -> src.getIssuer() != null ? src.getIssuer().getOrganization() : null,
                        CertificateDTO::setIssuerO)
                .addMapping(src -> src.getIssuer() != null ? src.getIssuer().getOrganizationalUnit() : null,
                        CertificateDTO::setIssuerOU);
    }

    public CertificateDTO toDTO(Certificate certificate) {
        if (certificate == null) return null;
        return modelMapper.map(certificate, CertificateDTO.class);
    }
}
