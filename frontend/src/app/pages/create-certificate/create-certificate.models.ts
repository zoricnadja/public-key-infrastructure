export interface Subject {
  commonName: string;
  organization: string;
  organizationUnit?: string;
  country?: string;
  state?: string;
  locality?: string;
  email?: string;
}

export interface Extension {
  oid: string;
  name?: string;
  isCritical?: boolean;
  value?: string;
}

export interface CreateCertificateRequest {
  issuerSerialNumber?: string;
  issuerCertificateType?: string;
  subject: Subject;
  extensions?: Extension[];
  issued?: string;
  expires: string;
  type: string;
}

export interface Certificate {
  serialNumber: string;
  type?: string;
  issued?: Date;
  expires?: Date;
  signatureAlgorithm?: string;
  subjectCN?: string;
  subjectO?: string;
  subjectOU?: string;
  issuerCN?: string;
  issuerO?: string;
  issuerOU?: string;
}
