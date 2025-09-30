package com.example.publickeyinfrastructure.mapper;

import com.example.publickeyinfrastructure.dto.ExtensionDTO;
import com.example.publickeyinfrastructure.model.CertificateExtension;
import com.example.publickeyinfrastructure.model.ExtensionType;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

@Component
public class ExtensionMapper {

    private final ModelMapper mapper;

    public ExtensionMapper(ModelMapper mapper) {
        this.mapper = mapper;
    }

    public ExtensionDTO toDto(CertificateExtension extension) {
        ExtensionDTO dto = new ExtensionDTO();
        dto.setName(extension.getExtensionType().getDisplayName());
        dto.setOid(extension.getExtensionType().getOid());
        dto.setIsCritical(extension.getIsCritical());

        // Convert byte[] to String using UTF-8
        if (extension.getValue() != null) {
            dto.setValue(new String(extension.getValue(), StandardCharsets.UTF_8));
        }

        return dto;
    }

    public CertificateExtension toEntity(ExtensionDTO dto) {
        CertificateExtension extension = new CertificateExtension();
        extension.setExtensionType(ExtensionType.fromOid(dto.getOid()));
        extension.setIsCritical(dto.getIsCritical());

        // Convert String to byte[] using UTF-8
        if (dto.getValue() != null && !dto.getValue().isEmpty()) {
            extension.setValue(dto.getValue().getBytes(StandardCharsets.UTF_8));
        }

        return extension;
    }
}