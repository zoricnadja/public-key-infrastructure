import { Component, OnInit } from '@angular/core';
import { FormArray, FormBuilder, FormGroup, Validators } from '@angular/forms';
import { format } from 'date-fns';
import {
  ExtensionPayload,
  CreateCertificateRequestPayload,
  Certificate,
} from './create-certificate.models';
import { CertificateCreateService } from './create-certificate.service';
import { AuthService } from '../../auth/auth.service';

@Component({
  selector: 'app-certificate-create',
  templateUrl: './create-certificate.component.html',
  styleUrls: ['./create-certificate.component.scss'],
})
export class CertificateCreateComponent implements OnInit {
  form: FormGroup;
  caCertificates: Certificate[] = [];
  issuers: string[] = [];
  saving = false;
  isAdmin = false;
  result: any = null;
  error: string | null = null;
  format = 'yyyy-MM-dd';

  // common extensions to choose from (friendly name + OID)
  commonExtensions = [
    { name: 'BasicConstraints', oid: '2.5.29.19' },
    { name: 'KeyUsage', oid: '2.5.29.15' },
    { name: 'ExtendedKeyUsage', oid: '2.5.29.37' },
    { name: 'SubjectAltName', oid: '2.5.29.17' },
    { name: 'AuthorityKeyIdentifier', oid: '2.5.29.35' },
    { name: 'SubjectKeyIdentifier', oid: '2.5.29.14' },
    { name: 'CRLDistributionPoints', oid: '2.5.29.31' },
  ];

  constructor(
    private fb: FormBuilder,
    private service: CertificateCreateService,
    private authService: AuthService,
  ) {
    this.form = this.fb.group({
      issuerCertificateAlias: ['', null],
      subject: this.fb.group({
        commonName: ['', null],
        organization: ['', null],
        organizationalUnit: [''],
        country: [''],
        state: [''],
        locality: [''],
        email: ['', null],
      }),
      extensions: this.fb.array([]),
      issued: [''],
      expires: ['', null],
      type: ['END', Validators.required], 

    });
  }

  ngOnInit(): void {
    this.loadIssuers();
    this.isAdmin = this.authService.getUserRoles().includes('admin');
    console.log(this.isAdmin);
    // default: add a BasicConstraints extension for CA selection UI (optional)
    this.addExtension({
      oid: '2.5.29.19',
      name: 'BasicConstraints',
      critical: true,
      value: 'CA:false',
    });
  }

  get extensions(): FormArray {
    return this.form.get('extensions') as FormArray;
  }

  addExtension(data?: Partial<ExtensionPayload>) {
    const group = this.fb.group({
      oid: [data?.oid || '', Validators.required],
      name: [data?.name || ''],
      critical: [data?.critical || false],
      value: [data?.value || '', Validators.required],
    });
    this.extensions.push(group);
  }

  removeExtension(index: number) {
    this.extensions.removeAt(index);
  }

  addCommonExtension(ext: { name: string; oid: string; critical?: boolean; value?: string }) {
    this.addExtension({
      oid: ext.oid,
      name: ext.name,
      critical: ext.critical,
      value: ext.value,
    });
  }

  loadIssuers() {
    this.service.getIssuers().subscribe({
      next: (certificates) => {
        this.issuers = certificates.map((cert) => `${cert.subjectCN}-${cert.subjectO}`);
      },
      error: () => (this.caCertificates = []),
    });
  }

  submit() {
    this.saving = true;
    this.error = null;
    const issuer = this.form.value.issuerCertificateAlias;
    let issuerValue;
    console.log(issuer)
    if (this.isAdmin && issuer === '') {
      issuerValue = undefined;
    } else {
      const index = this.issuers.findIndex(issuer);
      issuerValue = this.caCertificates.at(index)?.serialNumber;

    }
    const payload: CreateCertificateRequestPayload = {
      issuerSerialNumber: issuerValue,
      subject: this.form.value.subject,
      extensions: this.form.value.extensions,
      issued: this.form.value.issued
        ? format(new Date(this.form.value.issued), this.format)
        : format(new Date(), this.format),
      expires: format(new Date(this.form.value.expires), this.format),
      type: this.form.value.type,
    };

    this.service.createCertificate(payload).subscribe({
      next: (res) => {
        this.saving = false;
        this.result = res;
      },
      error: (err) => {
        this.saving = false;
        this.error = err?.error?.message || err?.message || 'Server error';
      },
    });
  }
}
