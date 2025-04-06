import {
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import axios from 'axios';
import {
  CognitoIdentityProviderClient,
  GetUserCommand,
  InitiateAuthCommand,
  InitiateAuthCommandOutput,
  InitiateAuthCommandInput,
  AdminCreateUserCommand,
  AdminDeleteUserCommand,
  AdminGetUserCommand,
  AdminListGroupsForUserCommand,
  AdminUpdateUserAttributesCommand,
  AdminAddUserToGroupCommand,
  AdminRemoveUserFromGroupCommand,
  ListUsersCommand,
  GetUserCommandOutput,
  GlobalSignOutCommand,
  AdminUserGlobalSignOutCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import { CognitoPayload } from './cognito.interface';
import { Role } from '../../admin/roles/role.enum';
import { CreateUserDto, UpdateUserDto, UserDto } from '../../user/dto';
import * as jwt from 'jsonwebtoken';
import * as jwksClient from 'jwks-rsa';
import {
  Response as ExpressResponse,
  Request as ExpressRequest,
} from 'express';

@Injectable()
export class CognitoService {
  private cognitoClient: CognitoIdentityProviderClient;
  // JWKS for token verification
  private readonly jwksUri: string;
  private readonly jwks: jwksClient.JwksClient;
  constructor() {
    this.cognitoClient = new CognitoIdentityProviderClient({
      region: process.env.AWS_REGION,
    });
    this.jwksUri = `https://cognito-idp.${process.env.AWS_REGION}.amazonaws.com/${process.env.COGNITO_USER_POOL_ID}/.well-known/jwks.json`;
    this.jwks = jwksClient({ jwksUri: this.jwksUri });
  }

  async getGoogleLoginRedirectUrl(): Promise<string> {
    const COGNITO_DOMAIN = process.env.COGNITO_DOMAIN;
    const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
    const REDIRECT_URI = process.env.COGNITO_REDIRECT_URI;

    // Validate env vars
    if (!COGNITO_DOMAIN || !CLIENT_ID || !REDIRECT_URI) {
      throw new InternalServerErrorException(
        'Missing Cognito configuration for Google login',
      );
    }
    const googleOAuthDomain = 'https://accounts.google.com/o/oauth2/v2/auth';
    return (
      `${googleOAuthDomain}` +
      `?response_type=code` +
      `&client_id=${CLIENT_ID}` +
      `&redirect_uri=${REDIRECT_URI}/google` +
      `&scope=email+openid+profile`
    );
  }
  async validateToken(token: string): Promise<any> {
    if (!token) {
      throw new UnauthorizedException('Token is missing');
    }

    try {
      // Decode token to get the kid
      const decodedJwt = jwt.decode(token, { complete: true });
      if (!decodedJwt || !decodedJwt.header || !decodedJwt.header.kid) {
        throw new UnauthorizedException('Invalid token');
      }

      const key = await this.jwks.getSigningKey(decodedJwt.header.kid);
      const signingKey = key.getPublicKey();

      // Verify token using the correct signing key
      const payload = jwt.verify(token, signingKey, { algorithms: ['RS256'] });
      // Type guard to check if it's a JwtPayload
      if (typeof payload === 'string' || !('username' in payload)) {
        throw new Error('Authentication failed: No User');
      }

      const uInfo = await this.getUserInfo(payload.username);
      if (!uInfo) {
        throw new Error('Authentication failed: No User link in prisma');
      }

      return uInfo;
    } catch (error) {
      console.error('Token validation failed:', error);
      throw new UnauthorizedException('Invalid or expired token');
    }
  }
  async exchangeGoogleToken(idToken: string): Promise<any> {
    const clientId = process.env.GOOGLE_CLIENT_ID!;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET!;
    const redirectUri = process.env.COGNITO_REDIRECT_URI!;

    // Ensure required environment variables are available
    if (!clientId || !clientSecret || !redirectUri) {
      throw new Error(
        'Missing required environment variables: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, or GOOGLE_REDIRECT_URI.',
      );
    }

    // Prepare the POST request to Google's OAuth2 token endpoint
    const url = 'https://oauth2.googleapis.com/token';

    const params = new URLSearchParams();
    params.append('grant_type', 'authorization_code');
    params.append('code', idToken); // The code received from the Google login
    params.append('client_id', clientId);
    params.append('client_secret', clientSecret);
    params.append('redirect_uri', `${redirectUri}/google`);

    console.log('Params:', params.toString()); // Log the params to debug

    const headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
    };

    try {
      const response = await axios.post(url, params, { headers });
      console.log('Google OAuth Token Exchange Response:', response.data); // Log the response for debugging
      return response.data;
    } catch (error) {
      // Log the full error for better debugging
      console.error(
        'Error during Google token exchange:',
        error.response || error.message || error,
      );
      throw new Error(
        `Failed to exchange code for tokens: ${error.response?.data?.error_description || error.message}`,
      );
    }
  }
  async getUserFromToken(accessToken: string): Promise<CognitoPayload> {
    const url = `https://${process.env.COGNITO_DOMAIN}/oauth2/userInfo`;
    const headers = {
      Authorization: `Bearer ${accessToken}`,
    };

    const response = await axios.get(url, { headers });
    return response.data;
  }
  async authenticateUser(
    email: string,
    password: string,
  ): Promise<InitiateAuthCommandOutput | null> {
    const params: InitiateAuthCommandInput = {
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: process.env.COGNITO_CLIENT_ID,
      AuthParameters: {
        USERNAME: email,
        PASSWORD: password,
      },
    };

    try {
      const command = new InitiateAuthCommand(params);
      const authResult = await this.cognitoClient.send(command);

      if (!authResult.AuthenticationResult) {
        throw new Error('Authentication failed, no AuthenticationResult found');
      }

      return authResult;
    } catch (error) {
      console.error('Error during authentication:', error);
      throw new Error('Invalid credentials or authentication failed');
    }
  }
  async getUserInfoByAccessToken(accessToken: string): Promise<CognitoPayload> {
    try {
      // Use GetUserCommand with access token
      const userInfo: GetUserCommandOutput = await this.cognitoClient.send(
        new GetUserCommand({ AccessToken: accessToken }),
      );

      const attributes = userInfo.UserAttributes || [];

      const email =
        attributes.find((attr) => attr.Name === 'email')?.Value || '';
      const name = attributes.find((attr) => attr.Name === 'name')?.Value || '';
      const sub = attributes.find((attr) => attr.Name === 'sub')?.Value || '';
      const username = userInfo.Username || '';

      // Use AdminListGroupsForUser (requires username)
      const groupResult = await this.cognitoClient.send(
        new AdminListGroupsForUserCommand({
          Username: username,
          UserPoolId: process.env.COGNITO_USER_POOL_ID,
        }),
      );

      const groups =
        groupResult.Groups?.map((group) => group.GroupName).filter(Boolean) ||
        [];

      let role = Role.USER;
      if (groups.includes('admin')) {
        role = Role.ADMIN;
      } else if (groups.includes('superadmin')) {
        role = Role.SUPERADMIN;
      }

      const userPayload: CognitoPayload = {
        sub,
        email,
        name,
        role,
        Attributes: attributes.map((attr) => ({
          Name: attr.Name || '',
          Value: attr.Value || '',
        })),
        username,
        client_id: process.env.COGNITO_CLIENT_ID,
        groups,
      };

      return userPayload;
    } catch (error) {
      throw new Error(
        `Failed to get user info by access token: ${error.message}`,
      );
    }
  }
  async getUserInfo(username: string): Promise<CognitoPayload> {
    try {
      // Fetch user information from Cognito
      const userInfo = await this.cognitoClient.send(
        new AdminGetUserCommand({
          UserPoolId: process.env.COGNITO_USER_POOL_ID,
          Username: username,
        }),
      );

      if (!userInfo.Username) {
        throw new Error('Cognito Username is missing');
      }

      // Fetch user groups
      const groupResult = await this.cognitoClient.send(
        new AdminListGroupsForUserCommand({
          Username: username,
          UserPoolId: process.env.COGNITO_USER_POOL_ID,
        }),
      );

      // Ensure that only valid group names (strings) are included in the array
      const groups =
        groupResult.Groups?.map((group) => group.GroupName).filter(Boolean) ||
        [];
      // Check if the user is in a specific group to assign a role
      let role = Role.USER; // Default role

      // Check if the user belongs to a group and assign role accordingly
      if (groups.includes('admin')) {
        role = Role.ADMIN;
      } else if (groups.includes('superadmin')) {
        role = Role.SUPERADMIN;
      }

      // Extract user attributes
      const attributes = userInfo.UserAttributes || [];

      const email =
        attributes.find((attr) => attr.Name === 'email')?.Value || '';
      const name = attributes.find((attr) => attr.Name === 'name')?.Value || '';
      //const role = attributes.find(attr => attr.Name === 'custom:role')?.Value || 'user'; // Default to 'user' if not set
      const sub = attributes.find((attr) => attr.Name === 'sub')?.Value || '';

      // Build the CognitoPayload
      const userPayload: CognitoPayload = {
        sub: sub,
        email: email,
        name: name,
        role, // Including the base role and groups in the role field
        Attributes: attributes.map((attr) => ({
          Name: attr.Name || '',
          Value: attr.Value || '',
        })),
        username: username,
        client_id: process.env.COGNITO_CLIENT_ID,
        groups, // Added the groups to the payload
      };

      return userPayload;
    } catch (error) {
      throw new Error(`Failed to get user info: ${error.message}`);
    }
  }
  async getUserInfoBySub(sub: string): Promise<any> {
    try {
      // Fetch user information from Cognito
      const command = new ListUsersCommand({
        UserPoolId: process.env.COGNITO_USER_POOL_ID,
        Filter: `sub = "${sub}"`,
        Limit: 1,
      });

      const response = await this.cognitoClient.send(command);

      const user = response.Users?.[0];
      if (!user) {
        throw new Error('User not found');
      }

      console.log('User found:', user);
      return user;
    } catch (error) {
      console.error('Error fetching user by sub:', error);
      throw error;
    }
  }
  async getUserInfoByEmail(email: string): Promise<any> {
    try {
      // Fetch user information from Cognito
      const command = new ListUsersCommand({
        UserPoolId: process.env.COGNITO_USER_POOL_ID,
        Filter: `email = "${email}"`,
        Limit: 1,
      });

      const response = await this.cognitoClient.send(command);

      const user = response.Users?.[0];
      if (!user) {
        return false;
      }

      return user;
    } catch (error) {
      console.error('Error fetching user by email:', error);
      throw error;
    }
  }
  // Create a new user in Cognito
  async createUser(createUserDto: CreateUserDto): Promise<any> {
    const { username, email, name, role, image } = createUserDto;

    try {
      // Build user attributes array safely
      const userAttributes = [
        { Name: 'email', Value: email },
        { Name: 'name', Value: name },
        // Only include custom:role if it's defined
        //...(role ? [{ Name: 'custom:role', Value: role }] : []),
        // Only include custom:image if it's defined
        //...(image ? [{ Name: 'custom:image', Value: image }] : []),
      ];

      const command = new AdminCreateUserCommand({
        UserPoolId: process.env.COGNITO_USER_POOL_ID,
        Username: username,
        UserAttributes: userAttributes,
        MessageAction: 'SUPPRESS', // Suppress the email invitation
      });

      const result = await this.cognitoClient.send(command);
      await this.addUserToGroup(username, role);
      return result;
    } catch (error) {
      console.error('Error creating user:', error);
      throw new Error('Failed to create user');
    }
  }

  async updateUser(
    username: string,
    updateUserDto: UpdateUserDto,
  ): Promise<any> {
    try {
      const attributes: { name: string; value: string | boolean }[] = [];

      // Update email, name, etc.
      if (updateUserDto.email) {
        attributes.push({ name: 'email', value: updateUserDto.email });
      }
      if (updateUserDto.name) {
        attributes.push({ name: 'name', value: updateUserDto.name });
      }

      // Update email_verified if available
      if (updateUserDto.email_verified !== undefined) {
        attributes.push({
          name: 'email_verified',
          value: updateUserDto.email_verified,
        });
      }

      // Add user to groups (instead of custom attributes for group)
      if (updateUserDto.groups) {
        const groupCommand = new AdminAddUserToGroupCommand({
          UserPoolId: process.env.COGNITO_USER_POOL_ID,
          Username: username,
          GroupName: updateUserDto.groups.join(','), // Assumes groups are an array, adjust as needed
        });

        // Send the add user to group command
        await this.cognitoClient.send(groupCommand);
      }

      const command = new AdminUpdateUserAttributesCommand({
        UserPoolId: process.env.COGNITO_USER_POOL_ID,
        Username: username,
        UserAttributes: attributes.map((attr) => ({
          Name: attr.name,
          Value: attr.value.toString(),
        })),
      });

      const result = await this.cognitoClient.send(command);
      return result;
    } catch (error) {
      console.error('Error updating user:', error);
      throw new Error('Failed to update user');
    }
  }

  // Delete a user from Cognito
  async deleteUser(username: string): Promise<any> {
    try {
      const command = new AdminDeleteUserCommand({
        UserPoolId: process.env.COGNITO_USER_POOL_ID,
        Username: username,
      });

      const result = await this.cognitoClient.send(command);
      return result;
    } catch (error) {
      console.error('Error deleting user:', error);
      throw new Error('Failed to delete user');
    }
  }

  // Add user to a group
  async addUserToGroup(username: string, groupName: string): Promise<any> {
    try {
      const command = new AdminAddUserToGroupCommand({
        UserPoolId: process.env.COGNITO_USER_POOL_ID,
        Username: username,
        GroupName: groupName,
      });

      const result = await this.cognitoClient.send(command);
      return result;
    } catch (error) {
      console.error('Error adding user to group:', error);
      throw new Error('Failed to add user to group');
    }
  }

  // Remove user from a group
  async removeUserFromGroup(username: string, groupName: string): Promise<any> {
    try {
      const command = new AdminRemoveUserFromGroupCommand({
        UserPoolId: process.env.COGNITO_USER_POOL_ID,
        Username: username,
        GroupName: groupName,
      });

      const result = await this.cognitoClient.send(command);
      return result;
    } catch (error) {
      console.error('Error removing user from group:', error);
      throw new Error('Failed to remove user from group');
    }
  }

  // List all users
  async listUsers(): Promise<any> {
    try {
      const command = new ListUsersCommand({
        UserPoolId: process.env.COGNITO_USER_POOL_ID,
      });

      const result = await this.cognitoClient.send(command);
      return result.Users || [];
    } catch (error) {
      console.error('Error listing users:', error);
      throw new Error('Failed to list users');
    }
  }
  async logoutUser(
    accessToken: string,
    response: ExpressResponse,
  ): Promise<any> {
    if (!accessToken) {
      throw new Error('Access token is required');
    }

    try {
      const command = new GlobalSignOutCommand({
        AccessToken: accessToken,
      });

      await this.cognitoClient.send(command);

      return { message: 'User logged out successfully' };
    } catch (error: any) {
      console.error('Error during logout:', error);
      throw new Error(error.message || 'Logout failed');
    }
  }

  async adminLogoutUser(username: string) {
    try {
      const command = new AdminUserGlobalSignOutCommand({
        UserPoolId: process.env.COGNITO_USER_POOL_ID,
        Username: username,
      });
      await this.cognitoClient.send(command);
      return { message: 'User forcefully logged out by admin' };
    } catch (error: any) {
      throw new Error(error.message || 'Admin logout failed');
    }
  }
}
