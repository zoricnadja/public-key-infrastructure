package com.example.publickeyinfrastructure.dto;

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
    private String type;
    private Date issued;
    private Date expires;
    private String signatureAlgorithm;
    private String subjectCN;
    private String subjectO;
    private String subjectOU;
    private String issuerCN;
    private String issuerO;
    private String issuerOU;
}
