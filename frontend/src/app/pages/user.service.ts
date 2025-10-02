import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../enviroment/environment';
import { User } from './user.models';

@Injectable({
  providedIn: 'root',
})
export class UserService {
  constructor(private http: HttpClient) {}

  getCaUsers(): Observable<User[]> {
    return this.http.get<User[]>(environment.apiUrl + '/users/ca');
  }

  assign(serialNumber: string, userId: number): Observable<string> {
    return this.http.put<string>(
      environment.apiUrl + '/users/assignment',
      {
        serialNumber,
        userId,
      },
      { responseType: 'text' as 'json'},
    );
  }
}
