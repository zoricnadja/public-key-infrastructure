package com.example.publickeyinfrastructure.mapper;

import com.example.publickeyinfrastructure.dto.CertificateEntityDTO;
import com.example.publickeyinfrastructure.dto.X500NameDTO;
import com.example.publickeyinfrastructure.model.CertificateEntity;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.modelmapper.ModelMapper;
import org.bouncycastle.asn1.x500.RDN;
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
        return mapper.map(subject, CertificateEntityDTO.class);
    }

    public CertificateEntity toEntity(X500NameDTO dto) {
        return mapper.map(dto, CertificateEntity.class);
    }

    public CertificateEntity toEntity(X500Name x500Name) {
        CertificateEntity entity = new CertificateEntity();

        entity.setCommonName(getRdnValue(x500Name, BCStyle.CN));
        entity.setOrganization(getRdnValue(x500Name, BCStyle.O));
        entity.setOrganizationalUnit(getRdnValue(x500Name, BCStyle.OU));
        entity.setCountry(getRdnValue(x500Name, BCStyle.C));
        entity.setState(getRdnValue(x500Name, BCStyle.ST));
        entity.setLocality(getRdnValue(x500Name, BCStyle.L));
        entity.setEmail(getRdnValue(x500Name, BCStyle.E));

        return entity;
    }

    private String getRdnValue(X500Name x500Name, org.bouncycastle.asn1.ASN1ObjectIdentifier identifier) {
        RDN[] rdns = x500Name.getRDNs(identifier);
        if (rdns != null && rdns.length > 0) {
            AttributeTypeAndValue atv = rdns[0].getFirst();
            if (atv != null) {
                return atv.getValue().toString();
            }
        }
        return null;
    }

}
