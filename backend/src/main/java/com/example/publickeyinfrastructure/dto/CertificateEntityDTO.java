package com.example.publickeyinfrastructure.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class CertificateEntityDTO extends X500NameDTO{
    private String publicKey;
}
