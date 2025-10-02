import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../enviroment/environment';
import { Certificate } from './create-certificate/create-certificate.models';

@Injectable({
  providedIn: 'root',
})
export class CertificateService {
  constructor(private http: HttpClient) {}

  getAllUnassigned(): Observable<Certificate[]> {
    return this.http.get<Certificate[]>(environment.apiUrl + '/certificates/unassigned');
  }

  revokeCertificate(serialNumber: string, reason: number): Observable<void> {
    return this.http.post<void>(environment.apiUrl + '/certificates/revoke', { serialNumber, reason });
  }
}
