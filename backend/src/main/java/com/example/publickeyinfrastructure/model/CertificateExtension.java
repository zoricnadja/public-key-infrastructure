package com.example.publickeyinfrastructure.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Arrays;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "certificate_extensions")
public class CertificateExtension {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    //todo check
    @Column
    private Boolean isCritical = false;

    @Lob
    private byte[] value;

    @Enumerated(EnumType.STRING)
    @Column
    private ExtensionType extensionType;


    @Override
    public String toString() {
        return "CertificateExtension{" +
                "id=" + id +
                ", isCritical=" + isCritical +
                ", extensionType=" + extensionType.getDisplayName() +
                ", valueString='" + Arrays.toString(value) + '\'' +
                '}';
    }
}