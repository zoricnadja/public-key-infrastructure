package com.example.publickeyinfrastructure.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ExtensionDTO {
    private String oid;
    private String name;
    private String value;
    private Boolean isCritical;

    @Override
    public String toString() {
        return "ExtensionDTO{" +
                "oid='" + oid + '\'' +
                ", name='" + name + '\'' +
                ", value='" + value + '\'' +
                ", isCritical=" + isCritical +
                '}';
    }
}
