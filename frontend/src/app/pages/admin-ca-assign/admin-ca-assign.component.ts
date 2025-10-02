import { Component, OnInit } from '@angular/core';
import { Certificate } from '../create-certificate/create-certificate.models';
import { AuthService } from '../../auth/auth.service';
import { UserService } from '../user.service';
import { CertificateService } from '../certificate.service';
import { User } from '../user.models';

@Component({
  selector: 'app-admin-ca-assign',
  templateUrl: './admin-ca-assign.component.html',
  styleUrls: ['./admin-ca-assign.component.scss'],
})
export class AdminCaAssignComponent implements OnInit {
  certificates: Certificate[] = [];
  users: User[] = [];
  loading = true;
  error: string | null = null;
  isAdmin = false;

  constructor(
    private userService: UserService,
    private certificateService: CertificateService,
    private auth: AuthService,
  ) {}

  ngOnInit(): void {
    this.isAdmin = this.auth.getUserRoles().includes('admin');
    if (!this.isAdmin) return;
    this.certificateService.getAllUnassigned().subscribe({
      next: (certs) => {
        this.certificates = certs;
        this.loading = false;
      },
      error: (err) => {
        this.error = err?.error?.message || err?.message || 'Server error';
        this.loading = false;
      },
    });
    this.userService.getCaUsers().subscribe({
      next: (users) => {
        this.users = users;
        this.loading = false;
      },
      error: (err) => {
        this.error = err?.error?.message || err?.message || 'Server error';
        this.loading = false;
      },
    });
  }

  assignToUser(serialNumber?: string, userId?: string) {
    console.log(serialNumber, userId);
    if (!serialNumber || !userId) return;

    const user = this.users.find((u) => u.id.toString() === userId);
    if (!user) return;

    console.log(serialNumber, user);

    this.loading = true;
    user.certificateSerialNumbers.push(serialNumber);
    console.log(user);
    this.userService.assign(serialNumber, Number(userId)).subscribe({
      next: () => {
        this.loading = false;
        console.log('Assignment successful');

        this.certificateService.getAllUnassigned().subscribe({
          next: (certs) => {
            this.certificates = certs;
            this.loading = false;
          },
          error: (err) => {
            this.error = err?.error?.message || err?.message || 'Server error';
            this.loading = false;
          },
        });
      },
      error: (err) => {
        this.error = err?.error?.message || err?.message || 'Server error';
        this.loading = false;
      },
    });
  }
}
