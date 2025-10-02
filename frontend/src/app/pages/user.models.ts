export interface User {
  id: number;
  keycloakId: string;
  email: string;
  firstName: string;
  lastName: string;
  organization: string;
  role: string;
  certificateSerialNumbers: string[];
}
