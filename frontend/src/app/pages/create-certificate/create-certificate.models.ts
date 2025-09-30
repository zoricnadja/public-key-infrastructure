export interface SubjectPayload {
  commonName: string;
  organization: string;
  organizationUnit?: string;
  country?: string;
  state?: string;
  locality?: string;
  email?: string;
}

export interface ExtensionPayload {
  oid: string;
  name?: string;
  critical?: boolean;
  value?: string;
}

export interface CreateCertificateRequestPayload {
  issuerSerialNumber?: string;
  subject: SubjectPayload;
  extensions?: ExtensionPayload[];
  issued?: string;
  expires: string;
  type: string;
}

export interface Certificate {
  serialNumber?: string;
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