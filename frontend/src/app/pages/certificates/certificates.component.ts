import { Component, OnInit } from '@angular/core';
import { CertificateCreateService } from '../create-certificate/create-certificate.service';
import { Certificate } from '../create-certificate/create-certificate.models';
import { CertificateService } from '../certificate.service';

@Component({
  selector: 'app-certificates',
  templateUrl: './certificates.component.html',
  styleUrls: ['./certificates.component.scss']
})
export class CertificatesComponent implements OnInit {
  certificates: Certificate[] = [];
  loading = true;
  error: string | null = null;

  revocationReasons = [
    { label: 'Unspecified', value: 0 },
    { label: 'Key Compromise', value: 1 },
    { label: 'CA Compromise', value: 2 },
    { label: 'Affiliation Changed', value: 3 },
    { label: 'Superseded', value: 4 },
    { label: 'Cessation Of Operation', value: 5 },
    { label: 'Certificate Hold', value: 6 },
    { label: 'Remove From CRL', value: 8 },
    { label: 'Privilege Withdrawn', value: 9 },
    { label: 'AA Compromise', value: 10 }
  ];
  selectedReasons: { [serial: string]: number } = {};

  constructor(
    private certificateCreateService: CertificateCreateService,
    private certificateService: CertificateService,
  ) {}

  ngOnInit(): void {
    this.fetchCertificates();
  }

  private fetchCertificates(): void {
    this.certificateCreateService.getCertificates().subscribe({
      next: (certs) => {
        this.certificates = certs;
        this.loading = false;
      },
      error: (err) => {
        this.error = err?.error?.message || err?.message || 'Server error';
        this.loading = false;
      }
    });
  }

  revokeCertificate(cert: Certificate): void {
    const reason = this.selectedReasons[cert.serialNumber] ?? 0;
    this.loading = true;
    this.certificateService.revokeCertificate(cert.serialNumber, reason).subscribe({
      next: () => {
        this.fetchCertificates();
      },
      error: (err) => {
        this.error = err?.error?.message || err?.message || 'Failed to revoke certificate';
        this.loading = false;
      }
    });
  }
}
