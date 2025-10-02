package com.example.publickeyinfrastructure.dto;

import com.example.publickeyinfrastructure.model.CertificateType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;
import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Setter
@Getter
public class CreateCertificateRequest {
    private String issuerSerialNumber;
    private CertificateType issuerCertificateType;
    private X500NameDTO subject;
    private List<ExtensionDTO> extensions;
    private Date issued;
    private Date expires;
    private CertificateType type;
    private String csrPem;
    private boolean autoGenerate;


    @Override
    public String toString() {
        return "CreateCertificateRequest{" +
                "issuerSerialNumber='" + issuerSerialNumber + '\'' +
                ", subject=" + subject +
                ", extensions=" + extensions +
                ", issued=" + issued +
                ", expires=" + expires +
                ", type='" + type  +
                ", issuerType='" + issuerCertificateType + '\'' +
                '}';
    }
}
