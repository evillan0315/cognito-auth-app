export interface CognitoPayload {
  sub: string; // The Cognito user ID
  email: string; // User's email address
  name: string; // User's name
  role: any; // User's role
  accessToken?: string; // Access token used for making API requests
  Attributes: {
    // List of custom attributes for the user
    Name: string; // Attribute name
    Value: string; // Attribute value
  }[];
  username: string; // Cognito Username
  client_id?: string; // Audience claim (should match the client ID)
  groups: any; // List of group names the user is part of
}
