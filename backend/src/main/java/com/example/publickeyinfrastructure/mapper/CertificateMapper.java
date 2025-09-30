package com.example.publickeyinfrastructure.mapper;

import com.example.publickeyinfrastructure.dto.CertificateDTO;
import com.example.publickeyinfrastructure.dto.CreateCertificateRequest;
import com.example.publickeyinfrastructure.model.Certificate;
import com.example.publickeyinfrastructure.model.CertificateType;
import org.modelmapper.ModelMapper;
import org.modelmapper.PropertyMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class CertificateMapper {

    private static final Logger logger = LoggerFactory.getLogger(CertificateMapper.class);
    private final ModelMapper mapper;
    private final ExtensionMapper extensionMapper;
    private final CertificateEntityMapper entityMapper;
    private final X500NameMapper x500NameMapper;

    @Autowired
    public CertificateMapper(ModelMapper mapper, CertificateEntityMapper entityMapper, ExtensionMapper extensionMapper, X500NameMapper x500NameMapper) {
        this.mapper = mapper;
        this.extensionMapper = extensionMapper;
        this.entityMapper = entityMapper;
        this.x500NameMapper = x500NameMapper;

//        mapper.addMappings(new PropertyMap<Certificate, CertificateDTO>() {
//            @Override
//            protected void configure() {
//                map().setSerialNumber(source.getSerialNumber());
//                map().setIssued(source.getIssued());
//                map().setExpires(source.getExpires());
//                map().setSignatureAlgorithm(source.getSignatureAlgorithm());
//
//                using(ctx -> entityMapper.toDto(((Certificate) ctx.getSource()).getSubject()))
//                        .map(source, destination.getSubject());
//
//                using(ctx -> entityMapper.toDto(((Certificate) ctx.getSource()).getIssuer()))
//                        .map(source, destination.getIssuer());
//            }
//        });

        mapper.addMappings(new PropertyMap<CertificateDTO, Certificate>() {
            @Override
            protected void configure() {
                map().setSerialNumber(source.getSerialNumber());

                map().setIssued(source.getIssued());
                map().setExpires(source.getExpires());
                map().setSignatureAlgorithm(source.getSignatureAlgorithm());

                using(ctx -> entityMapper.toEntity(((CertificateDTO) ctx.getSource()).getSubject()))
                        .map(source, destination.getSubject());

                using(ctx -> entityMapper.toEntity(((CertificateDTO) ctx.getSource()).getIssuer()))
                        .map(source, destination.getIssuer());
            }
        });

        //todo map issuer certificate serial number
//        mapper.addMappings(new PropertyMap<CreateCertificateRequest, Certificate>() {
//            @Override
//            protected void configure() {
//
//                using(ctx -> ((CreateCertificateRequest) ctx.getSource()).getExtensions().stream().map(extensionMapper::toEntity))
//                        .map(source, destination.getExtensions());
//                logger.debug("ovo je -1");
//
//            }
//        });
    }

    public CertificateDTO toDto(Certificate certificate) {
        return mapper.map(certificate, CertificateDTO.class);
    }

    public Certificate toEntity(CertificateDTO dto) {
        return mapper.map(dto, Certificate.class);
    }

    public Certificate toEntity(CreateCertificateRequest request) {
        logger.debug("ovo je zahtev-> cert - {}", request.toString());
        Certificate certificate = mapper.map(request, Certificate.class);
        logger.debug("ovo je zahtev-> cert - {}", certificate.toString());
        certificate.setSubject(x500NameMapper.toEntity(request.getSubject()));
        logger.debug("ovo je zahtev-> cert - {}", certificate.toString());
        certificate.setExtensions(request.getExtensions().stream().map(extensionMapper::toEntity).toList());
        logger.debug("ovo je zahtev-> cert - {}", certificate.getExtensions().toString());
        return certificate;
    }
}
