package com.example.publickeyinfrastructure.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class X500NameDTO {
    private String commonName;
    private String email;
    private String country;
    private String organization;
    private String organizationalUnit;
    private String state;
    private String locality;

    @Override
    public String toString() {
        return "X500NameDTO{" +
                "commonName='" + commonName + '\'' +
                ", email='" + email + '\'' +
                ", country='" + country + '\'' +
                ", organization='" + organization + '\'' +
                ", organizationalUnit='" + organizationalUnit + '\'' +
                ", state='" + state + '\'' +
                ", locality='" + locality + '\'' +
                '}';
    }
}
