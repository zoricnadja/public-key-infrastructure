package com.example.publickeyinfrastructure.mapper;

import com.example.publickeyinfrastructure.dto.ExtensionDTO;
import com.example.publickeyinfrastructure.model.Certificate;
import com.example.publickeyinfrastructure.model.CertificateExtension;
import com.example.publickeyinfrastructure.model.ExtensionType;
import org.springframework.stereotype.Component;

@Component
public class ExtensionMapper {

    /**
     * Mapira ExtensionDTO u CertificateExtension entitet i povezuje ga sa sertifikatom
     */
    public CertificateExtension fromDTO(ExtensionDTO dto, Certificate certificate) {
        if (dto == null) return null;
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate must not be null when mapping extension");
        }

        CertificateExtension extension = new CertificateExtension();
        extension.setOid(dto.getOid());
        extension.setName(dto.getName());
        extension.setValueString(dto.getValue());
        extension.setIsCritical(dto.getCritical() != null ? dto.getCritical() : false);
        extension.setCertificate(certificate);
        extension.setExtensionType(mapNameToExtensionType(dto.getName()));
        return extension;
    }

    /**
     * Mapira CertificateExtension entitet u DTO
     */
    public ExtensionDTO toDTO(CertificateExtension extension) {
        if (extension == null) return null;

        return new ExtensionDTO(
                extension.getOid(),
                extension.getName(),
                extension.getValueString(),
                extension.getIsCritical()
        );
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

