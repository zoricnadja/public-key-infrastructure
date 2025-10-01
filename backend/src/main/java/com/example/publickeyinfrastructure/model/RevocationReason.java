package com.example.publickeyinfrastructure.model;

public enum RevocationReason {
    UNSPECIFIED,
    KEY_COMPROMISE,
    CA_COMPROMISE,
    AFFILIATION_CHANGED,
    SUPERSEDED,
    CESSATION_OF_OPERATION,
    CERTIFICATE_HOLD,
    PRIVILEGE_WITHDRAWN,
    AA_COMPROMISE,
    WEAK_ALGORITHM_OR_KEY
}
