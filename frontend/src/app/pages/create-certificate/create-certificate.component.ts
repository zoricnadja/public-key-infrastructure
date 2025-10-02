import { Component, OnInit } from '@angular/core';
import { FormArray, FormBuilder, FormGroup, Validators } from '@angular/forms';
import { format } from 'date-fns';
import { Extension, CreateCertificateRequest, Certificate } from './create-certificate.models';
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
  saving = false;
  isAdmin = false;
  isCA = false;
  result: any = null;
  error: string | null = null;
  format = 'yyyy-MM-dd';
  csrError: string | null = null;

  commonExtensions = [
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
    const futureDateValidator = (control: any) => {
      if (!control.value) return null;
      const inputDate = new Date(control.value);
      const now = new Date();
      inputDate.setHours(0, 0, 0, 0);
      now.setHours(0, 0, 0, 0);
      return inputDate > now ? null : { notFutureDate: true };
    };

    this.form = this.fb.group({
      creationMode: ['auto', null],
      issuerCertificateAlias: ['', null],
      subject: this.fb.group({
        commonName: ['', Validators.required],
        organization: ['', Validators.required],
        organizationalUnit: ['', Validators.required],
        country: ['', Validators.required],
        state: ['', Validators.required],
        locality: ['', Validators.required],
        email: ['', Validators.email],
      }),
      extensions: this.fb.array([]),
      issued: [''],
      expires: ['', [Validators.required, futureDateValidator]],
      type: ['END_ENTITY', Validators.required],
    });
  }

  onCsrFileChange(event: any) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
      this.form.addControl('csrPem', this.fb.control(reader.result as string));
    };
    reader.onerror = () => {
      this.csrError = 'Failed to read CSR file';
    };
    reader.readAsText(file);
  }
  ngOnInit(): void {
    this.loadIssuers();
    this.isAdmin = this.authService.getUserRoles().includes('admin');
    this.isCA = this.authService.getUserRoles().includes('ca-user');
    console.log(this.isAdmin);
    console.log(this.authService.getUserRoles());
    console.log(this.isCA);
  }

  get extensions(): FormArray {
    return this.form.get('extensions') as FormArray;
  }

  addExtension(data?: Partial<Extension>) {
    const group = this.fb.group({
      oid: [data?.oid || '', Validators.required],
      name: [data?.name || ''],
      isCritical: [data?.isCritical || false],
      value: [data?.value || '', Validators.required],
    });
    this.extensions.push(group);
  }

  removeExtension(index: number) {
    this.extensions.removeAt(index);
  }

  addCommonExtension(ext: { name: string; oid: string; isCritical?: boolean; value?: string }) {
    let defaultValue = '';

    switch (ext.name) {
      case 'KeyUsage':
        defaultValue = 'digitalSignature,keyEncipherment';
        break;

      case 'ExtendedKeyUsage':
        defaultValue = 'serverAuth,clientAuth';
        break;

      case 'SubjectAltName':
        defaultValue = 'DNS=example.com,IP=127.0.0.1,email=user@example.com';
        break;

      case 'AuthorityKeyIdentifier':
      case 'SubjectKeyIdentifier':
        defaultValue = 'auto';
        break;

      case 'CRLDistributionPoints':
        defaultValue = 'http://example.com/crl.pem';
        break;
    }

    this.addExtension({
      oid: ext.oid,
      name: ext.name,
      isCritical: ext.isCritical ?? true,
      value: defaultValue,
    });
  }

  getPlaceholder(value: string): string {
    if (!value) return 'Enter extension value';
    return value;
  }

  loadIssuers() {
    this.service.getIssuers().subscribe({
      next: (certificates) => {
        this.caCertificates = certificates;
      },
      error: () => (this.caCertificates = []),
    });
  }

  submit() {
    this.form.markAllAsTouched();

    if (this.form.invalid && this.form.get('creationMode')?.value === 'auto') {
      this.error = 'Please fix the errors before generating the certificate.';
      return;
    }
    let issuer = this.form.value.issuerCertificateAlias;
    if (this.isAdmin && issuer === '') issuer = undefined;
    if (!issuer && !this.isAdmin) {
      this.error = 'Please select issuer';
      return;
    }
    const payload: CreateCertificateRequest = {
      issuerSerialNumber: issuer?.serialNumber,
      issuerCertificateType: issuer?.type,
      subject: this.form.value.subject,
      extensions: this.form.value.extensions,
      issued: this.form.value.issued
        ? format(new Date(this.form.value.issued), this.format)
        : format(new Date(), this.format),
      expires: format(new Date(this.form.value.expires), this.format),
      type: this.form.value.type,
      csrPem: this.form.value.csrPem,
    };
    console.log(payload);
    this.service.createCertificate(payload).subscribe({
      next: (res) => {
        this.saving = false;
        this.result = res;
        this.loadIssuers();
      },
      error: (err) => {
        this.saving = false;
        this.error = err?.error?.message || err?.message || 'Server error';
      },
    });
  }
}
