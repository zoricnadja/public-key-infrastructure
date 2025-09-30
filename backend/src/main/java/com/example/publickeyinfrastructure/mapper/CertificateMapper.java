package com.example.publickeyinfrastructure.mapper;

import com.example.publickeyinfrastructure.dto.CertificateResponse;
import com.example.publickeyinfrastructure.dto.CreateCertificateRequest;
import com.example.publickeyinfrastructure.model.Certificate;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class CertificateMapper {

//    private static final Logger logger = LoggerFactory.getLogger(CertificateMapper.class);
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


    public Certificate toEntity(CreateCertificateRequest request) {
        Certificate certificate = mapper.map(request, Certificate.class);
        certificate.setSubject(x500NameMapper.toEntity(request.getSubject()));
        certificate.setExtensions(request.getExtensions().stream().map(extensionMapper::toEntity).toList());
        return certificate;
    }
}
