import { KeycloakService } from 'keycloak-angular';
import { environment } from '../../enviroment/environment';

const keycloakConfig = environment.keycloak;

export function initializeKeycloak(keycloak: KeycloakService) {
  return () =>
    keycloak.init({
      config: {
        url: keycloakConfig.url,
        realm: keycloakConfig.realm,
        clientId: keycloakConfig.clientId,
      },
      initOptions: {
        onLoad: 'login-required',
        checkLoginIframe: false,
      },
    });
}
