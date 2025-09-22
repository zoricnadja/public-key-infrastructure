package com.example.publickeyinfrastructure.model;

import com.example.publickeyinfrastructure.mapper.X500NameBuilder;
import jakarta.persistence.Column;
import jakarta.persistence.Id;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Entity;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.bouncycastle.asn1.x500.X500Name;

import java.security.PublicKey;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "subjects")
public class Subject implements HasX500Fields{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private PublicKey publicKey;

    @Column
    private String commonName;

    @Column
    private String organization;

    @Column
    private String organizationalUnit;

    @Column
    private String country;

    @Column
    private String state;

    @Column
    private String locality;

    @Column
    private String email;

    @Transient
    public X500Name getX500Name() {
        return X500NameBuilder.buildX500Name(this);
    }
}