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

    public ExtensionDTO toDto(CertificateExtension extension) {
        ExtensionDTO dto = mapper.map(extension, ExtensionDTO.class);
        dto.setName(extension.getExtensionType().getDisplayName());
        dto.setOid(extension.getExtensionType().getOid());
        return dto;
    }

    public CertificateExtension toEntity(ExtensionDTO dto) {
        CertificateExtension extension = mapper.map(dto, CertificateExtension.class);
        extension.setExtensionType(ExtensionType.fromOid(dto.getOid()));
        return extension;
    }
}