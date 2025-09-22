package com.example.publickeyinfrastructure.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.bouncycastle.asn1.x509.Extension;

import java.util.Date;
import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Setter
@Getter
public class CreateCertificateRequest {
    private String issuerCertificateAlias;
    private SubjectDTO subject;
    private List<Extension> extensions;
    private Date issued;
    private Date expires;
}
