package com.example.publickeyinfrastructure.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class SubjectDTO {
    private String commonName;
    private String email;
    private String country;
    private String organization;
    private String organizationalUnit;
    private String state;
    private String locality;
}
