import { Component, OnInit } from '@angular/core';
import { CertificateCreateService } from '../create-certificate/create-certificate.service';
import { Certificate } from '../create-certificate/create-certificate.models';

@Component({
  selector: 'app-certificates',
  templateUrl: './certificates.component.html',
  styleUrls: ['./certificates.component.scss']
})
export class CertificatesComponent implements OnInit {
  certificates: Certificate[] = [];
  loading = true;
  error: string | null = null;

  constructor(private service: CertificateCreateService) {}

  ngOnInit(): void {
    this.service.getCertificates().subscribe({
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
}
