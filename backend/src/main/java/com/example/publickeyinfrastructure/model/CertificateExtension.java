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

    @Column(name = "oid", nullable = false)
    private String oid;

    @Column(name = "name")
    private String name;

    @Column(name = "is_critical", nullable = false)
    private Boolean isCritical = false;

    @Lob
    @Column(name = "value_bytes")
    private byte[] valueBytes;

    @Column(name = "value_string", columnDefinition = "TEXT")
    private String valueString;

    @Enumerated(EnumType.STRING)
    @Column(name = "extension_type")
    private ExtensionType extensionType;

    @Override
    public String toString() {
        return "CertificateExtension{" +
                "id=" + id +
                ", oid='" + oid + '\'' +
                ", name='" + name + '\'' +
                ", isCritical=" + isCritical +
                ", extensionType=" + extensionType +
                ", valueString='" + valueString + '\'' +
                '}';
    }
}