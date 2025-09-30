package com.example.publickeyinfrastructure.mapper;

import com.example.publickeyinfrastructure.config.Constants;
import com.example.publickeyinfrastructure.dto.CertificateEntityDTO;
import com.example.publickeyinfrastructure.dto.CreateCertificateRequest;
import com.example.publickeyinfrastructure.model.CertificateEntity;
import com.example.publickeyinfrastructure.util.KeyUtil;
import org.modelmapper.ModelMapper;
import org.modelmapper.PropertyMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class CertificateEntityMapper {
    private final ModelMapper mapper;
    private static final Logger logger = LoggerFactory.getLogger(CertificateEntityMapper.class);

    public CertificateEntityMapper(ModelMapper mapper) {
        this.mapper = mapper;
        mapper.addMappings(new PropertyMap<CertificateEntity, CertificateEntityDTO>() {
            @Override
            protected void configure() {
                using(ctx -> KeyUtil.publicKeyToBase64(((CertificateEntity) ctx.getSource()).getPublicKey()))
                        .map(source, destination.getPublicKey());
            }
        });

        mapper.addMappings(new PropertyMap<CertificateEntityDTO, CertificateEntity>() {
            @Override
            protected void configure() {
                using(ctx -> {
                    try {
                        return KeyUtil.base64ToPublicKey((String) ctx.getSource(), Constants.CRYPTO_ALGORITHM);
                    } catch (Exception e) {
                        throw new RuntimeException("Invalid public key", e);
                    }
                }).map(source.getPublicKey(), destination.getPublicKey());
            }
        });
    }

    public CertificateEntityDTO toDto(CertificateEntity entity) {
        logger.debug("ovo certE->dto - {}", mapper.map(entity, CertificateEntityDTO.class));

        return mapper.map(entity, CertificateEntityDTO.class);
    }

    public CertificateEntity toEntity(CertificateEntityDTO dto) {
        logger.debug("ovo dto->certEnt - {}", mapper.map(dto, CertificateEntity.class));
        return mapper.map(dto, CertificateEntity.class);
    }
}
