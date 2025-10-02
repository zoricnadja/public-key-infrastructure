import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HomeComponent } from './home/home.component';
import { AuthModule } from '../auth/auth.module';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { CertificateCreateComponent } from './create-certificate/create-certificate.component';
import { CertificatesComponent } from './certificates/certificates.component';

@NgModule({
  declarations: [HomeComponent, CertificateCreateComponent, CertificatesComponent],
  imports: [CommonModule, AuthModule, FormsModule, ReactiveFormsModule],
})
export class PagesModule {}
