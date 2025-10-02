package com.example.publickeyinfrastructure.dto;

import com.example.publickeyinfrastructure.model.RevocationReason;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RevocationRequest {
    private String serialNumber;
    private RevocationReason reason;
}
