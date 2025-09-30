package com.example.publickeyinfrastructure.mapper;

import com.example.publickeyinfrastructure.dto.CertificateEntityDTO;
import com.example.publickeyinfrastructure.dto.X500NameDTO;
import com.example.publickeyinfrastructure.model.CertificateEntity;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class X500NameMapper {
    private static final Logger logger = LoggerFactory.getLogger(X500NameMapper.class);

    private final ModelMapper mapper;

    public X500NameMapper(ModelMapper mapper) {
        this.mapper = mapper;
    }

    public X500NameDTO toDto(CertificateEntity subject) {
        logger.debug("mapiran entitet - x500 {}",mapper.map(subject, CertificateEntityDTO.class).toString());
        return mapper.map(subject, CertificateEntityDTO.class);
    }

    public CertificateEntity toEntity(X500NameDTO dto) {
        logger.debug("mapiran x500 - enititet {}",mapper.map(dto, CertificateEntity.class).toString());

        return mapper.map(dto, CertificateEntity.class);
    }
}
