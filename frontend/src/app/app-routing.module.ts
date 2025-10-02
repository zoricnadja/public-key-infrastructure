import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { HomeComponent } from './pages/home/home.component';
import { CertificatesComponent } from './pages/certificates/certificates.component';
import { CertificateCreateComponent } from './pages/create-certificate/create-certificate.component';
import { AuthGuard } from './auth/auth.guard';
import { AdminCaAssignComponent } from './pages/admin-ca-assign/admin-ca-assign.component';

const routes: Routes = [
  {
    path: '',
    component: HomeComponent,
    canActivate: [AuthGuard],
  },
  {
    path: 'certificates',
    component: CertificatesComponent,
    canActivate: [AuthGuard],
  },
  {
    path: 'create-certificate',
    component: CertificateCreateComponent,
    canActivate: [AuthGuard],
  },
  {
    path: 'admin-ca-assign',
    component: AdminCaAssignComponent,
    canActivate: [AuthGuard],
  },
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule],
})
export class AppRoutingModule {}
