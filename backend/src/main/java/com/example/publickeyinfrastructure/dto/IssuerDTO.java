package com.example.publickeyinfrastructure.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.security.PublicKey;

@NoArgsConstructor
@AllArgsConstructor
@Getter
public class IssuerDTO {
    private PublicKey publicKey;
    private String commonName;
    private String email;
    private String country;
    private String organization;
    private String organizationalUnit;
    private String state;
    private String locality;
}
