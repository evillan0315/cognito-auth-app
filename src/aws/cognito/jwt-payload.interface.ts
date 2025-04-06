export interface JwtPayload {
  sub: string; // The Cognito user ID
  email: string;
  name: string;
  accessToken: string;
}
