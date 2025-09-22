package com.example.publickeyinfrastructure.mapper;

import com.example.publickeyinfrastructure.dto.SubjectDTO;
import com.example.publickeyinfrastructure.model.HasX500Fields;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.springframework.stereotype.Component;

@Component
public class X500NameBuilder {

    private String getValue(X500Name x500Name, ASN1ObjectIdentifier identifier) {
        RDN[] rdns = x500Name.getRDNs(identifier);
        if (rdns != null && rdns.length > 0 && rdns[0].getFirst() != null) {
            return rdns[0].getFirst().getValue().toString();
        }
        return null;
    }

    public SubjectDTO fromX500Name(X500Name x500Name) {
        SubjectDTO dto = new SubjectDTO();
        dto.setCommonName(getValue(x500Name, BCStyle.CN));   // Common Name
        dto.setEmail(getValue(x500Name, BCStyle.EmailAddress)); // email
        dto.setCountry(getValue(x500Name, BCStyle.C)); // Country
        dto.setOrganization(getValue(x500Name, BCStyle.O)); // Organization
        dto.setOrganizationUnit(getValue(x500Name, BCStyle.OU)); // Org Unit
        return dto;
    }

    public static X500Name buildX500Name(HasX500Fields entity) {
        StringBuilder sb = new StringBuilder();

        if (entity.getCommonName() != null) sb.append("CN=").append(entity.getCommonName()).append(",");
        if (entity.getOrganization() != null) sb.append("O=").append(entity.getOrganization()).append(",");
        if (entity.getOrganizationalUnit() != null) sb.append("OU=").append(entity.getOrganizationalUnit()).append(",");
        if (entity.getCountry() != null) sb.append("C=").append(entity.getCountry()).append(",");
        if (entity.getState() != null) sb.append("ST=").append(entity.getState()).append(",");
        if (entity.getLocality() != null) sb.append("L=").append(entity.getLocality()).append(",");
        if (entity.getEmail() != null) sb.append("EMAILADDRESS=").append(entity.getEmail()).append(",");

        if (!sb.isEmpty() && sb.charAt(sb.length() - 1) == ',') {
            sb.deleteCharAt(sb.length() - 1);
        }

        return new X500Name(sb.toString());
    }
}

