import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HomeComponent } from './home/home.component';
import { AuthModule } from '../auth/auth.module';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { CertificateCreateComponent } from './create-certificate/create-certificate.component';
import { CertificatesComponent } from './certificates/certificates.component';
import { AdminCaAssignComponent } from './admin-ca-assign/admin-ca-assign.component';

@NgModule({
  declarations: [
    HomeComponent,
    CertificateCreateComponent,
    CertificatesComponent,
    AdminCaAssignComponent,
  ],
  imports: [CommonModule, AuthModule, FormsModule, ReactiveFormsModule],
})
export class PagesModule {}
