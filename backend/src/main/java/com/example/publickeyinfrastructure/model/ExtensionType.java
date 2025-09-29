package com.example.publickeyinfrastructure.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum ExtensionType {

    SUBJECT_ALTERNATIVE_NAME("2.5.29.17", "Subject Alternative Name"),
    KEY_USAGE("2.5.29.15", "Key Usage"),
    EXTENDED_KEY_USAGE("2.5.29.37", "Extended Key Usage"),
    BASIC_CONSTRAINTS("2.5.29.19", "Basic Constraints"),
    CERTIFICATE_POLICIES("2.5.29.32", "Certificate Policies"),
    AUTHORITY_KEY_IDENTIFIER("2.5.29.35", "Authority Key Identifier"),
    SUBJECT_KEY_IDENTIFIER("2.5.29.14", "Subject Key Identifier"),
    CRL_DISTRIBUTION_POINTS("2.5.29.31", "CRL Distribution Points"),
    AUTHORITY_INFORMATION_ACCESS("1.3.6.1.5.5.7.1.1", "Authority Information Access"),
    CUSTOM(null, "Custom Extension");

    private final String oid;
    private final String displayName;

    public static ExtensionType fromOid(String oid) {
        for (ExtensionType type : values()) {
            if (oid != null && oid.equals(type.getOid())) {
                return type;
            }
        }
        return CUSTOM;
    }
}
