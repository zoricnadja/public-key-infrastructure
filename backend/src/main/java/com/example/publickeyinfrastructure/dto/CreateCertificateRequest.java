package com.example.publickeyinfrastructure.dto;

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
    private SubjectDTO subject;
    private List<ExtensionDTO> extensions;
    private Date issued;
    private Date expires;
}
