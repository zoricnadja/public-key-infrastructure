package com.example.publickeyinfrastructure.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.x500.X500Name;

import java.security.PublicKey;

@NoArgsConstructor
@AllArgsConstructor
@Getter
public class IssuerDTO {
    private PublicKey publicKey;
    private X500Name x500Name;
}
