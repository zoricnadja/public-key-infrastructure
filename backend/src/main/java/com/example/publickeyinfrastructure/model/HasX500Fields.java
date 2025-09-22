package com.example.publickeyinfrastructure.model;

public interface HasX500Fields {
    String getCommonName();
    String getOrganization();
    String getOrganizationalUnit();
    String getCountry();
    String getState();
    String getLocality();
    String getEmail();
}
