import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Certificate, CreateCertificateRequestPayload } from './create-certificate.models';
import { environment } from '../../../enviroment/environment';

@Injectable({
  providedIn: 'root',
})
export class CertificateCreateService {
  constructor(private http: HttpClient) {}

  createCertificate(payload: CreateCertificateRequestPayload): Observable<any> {
    return this.http.post(environment.apiUrl + '/certificates', payload);
  }

  getIssuers(): Observable<Certificate[]> {
    return this.http.get<Certificate[]>(environment.apiUrl + '/certificates/issuers');
  }
}
