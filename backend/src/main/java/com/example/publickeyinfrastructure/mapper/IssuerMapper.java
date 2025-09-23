package com.example.publickeyinfrastructure.mapper;

import com.example.publickeyinfrastructure.dto.IssuerDTO;
import com.example.publickeyinfrastructure.model.Issuer;
import com.example.publickeyinfrastructure.util.KeyUtil;
import org.modelmapper.ModelMapper;
import org.modelmapper.PropertyMap;

public class IssuerMapper {
    private final ModelMapper mapper;

    public IssuerMapper(ModelMapper mapper) {
        this.mapper = mapper;
        mapper.addMappings(new PropertyMap<Issuer, IssuerDTO>() {
            @Override
            protected void configure() {
                using(ctx -> KeyUtil.publicKeyToBase64(((Issuer) ctx.getSource()).getPublicKey()))
                        .map(source, destination.getPublicKey());
            }
        });

        mapper.addMappings(new PropertyMap<IssuerDTO, Issuer>() {
            @Override
            protected void configure() {
                using(ctx -> {
                    try {
                        return KeyUtil.base64ToPublicKey((String) ctx.getSource(), "RSA");
                    } catch (Exception e) {
                        throw new RuntimeException("Invalid public key", e);
                    }
                }).map(source.getPublicKey(), destination.getPublicKey());
            }
        });
    }

    public IssuerDTO toDto(Issuer issuer) {
        return mapper.map(issuer, IssuerDTO.class);
    }

    public Issuer toEntity(IssuerDTO dto) {
        return mapper.map(dto, Issuer.class);
    }
}
