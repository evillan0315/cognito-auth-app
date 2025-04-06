// user.interface.ts
export interface User {
  sub: string;
  email: string; // User's email address
  name: string; // User's name
  role: any;
  username?: string; // Cognito Username
  client_id?: string; // Audience claim (should match the client ID)
  groups?: any;
}
