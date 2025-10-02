import { Injectable } from '@angular/core';
import { CanActivate, Router, UrlTree } from '@angular/router';
import { KeycloakService } from 'keycloak-angular';

@Injectable({ providedIn: 'root' })
export class AuthGuard implements CanActivate {
  constructor(
    private keycloak: KeycloakService,
    private router: Router,
  ) {}

  async canActivate(): Promise<boolean | UrlTree> {
    const authenticated = await this.keycloak.isLoggedIn();
    if (authenticated) {
      return true;
    }
    return this.router.parseUrl('/');
  }
}
