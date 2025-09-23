import { Injectable } from '@angular/core';
import { KeycloakService } from 'keycloak-angular';
import { environment } from '../../enviroment/environment';

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  constructor(private keycloak: KeycloakService) {}

  getUserRoles(): string[] {
    return this.keycloak.getUserRoles(true, environment.keycloak.clientId);
  }
  logout(): Promise<void> {
    return this.keycloak.logout();
  }
}
