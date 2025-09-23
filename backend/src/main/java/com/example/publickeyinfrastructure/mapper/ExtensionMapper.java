package com.example.publickeyinfrastructure.mapper;

import com.example.publickeyinfrastructure.dto.ExtensionDTO;
import com.example.publickeyinfrastructure.model.CertificateExtension;
import com.example.publickeyinfrastructure.model.ExtensionType;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;

@Component
public class ExtensionMapper {

    private final ModelMapper mapper;

    public ExtensionMapper(ModelMapper mapper) {
        this.mapper = mapper;
    }

    public ExtensionDTO toDto(CertificateExtension issuer) {
        return mapper.map(issuer, ExtensionDTO.class);
    }

    public CertificateExtension toEntity(ExtensionDTO dto) {
        CertificateExtension extension = mapper.map(dto, CertificateExtension.class);
        extension.setExtensionType(mapNameToExtensionType(dto.getName()));
        return extension;
    }
    private ExtensionType mapNameToExtensionType(String name) {
        if (name == null) return ExtensionType.CUSTOM;

        return switch (name) {
            case "BasicConstraints" -> ExtensionType.BASIC_CONSTRAINTS;
            case "KeyUsage" -> ExtensionType.KEY_USAGE;
            case "ExtendedKeyUsage" -> ExtensionType.EXTENDED_KEY_USAGE;
            case "SubjectAltName" -> ExtensionType.SUBJECT_ALTERNATIVE_NAME;
            case "AuthorityKeyIdentifier" -> ExtensionType.AUTHORITY_KEY_IDENTIFIER;
            case "SubjectKeyIdentifier" -> ExtensionType.SUBJECT_KEY_IDENTIFIER;
            case "CRLDistributionPoints" -> ExtensionType.CRL_DISTRIBUTION_POINTS;
            default -> ExtensionType.CUSTOM;
        };
    }

}

