package com.example.publickeyinfrastructure.dto;

import com.example.publickeyinfrastructure.model.CertificateType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class CertificateDTO {
    private String serialNumber;
    private CertificateType type;
    private Date issued;
    private Date expires;
    private String signatureAlgorithm;
    private CertificateEntityDTO subject;
    private CertificateEntityDTO issuer;
}
