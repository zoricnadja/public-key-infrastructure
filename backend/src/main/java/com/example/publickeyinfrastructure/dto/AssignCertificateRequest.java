package com.example.publickeyinfrastructure.dto;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class AssignCertificateRequest {
    private Integer userId;
    private String serialNumber;

}

