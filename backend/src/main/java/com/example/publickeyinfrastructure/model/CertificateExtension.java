package com.example.publickeyinfrastructure.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

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

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "certificate_id", nullable = false)
    private Certificate certificate;

    @Column
    private String oid;

    @Column
    private String name;

    @Column
    private Boolean isCritical = false;

    @Column
    private String value;

    @Enumerated(EnumType.STRING)
    @Column
    private ExtensionType extensionType;

    @Override
    public String toString() {
        return "CertificateExtension{" +
                "id=" + id +
                ", oid='" + oid + '\'' +
                ", name='" + name + '\'' +
                ", isCritical=" + isCritical +
                ", extensionType=" + extensionType +
                ", valueString='" + value + '\'' +
                '}';
    }
}