import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CognitoService } from '../aws/cognito/cognito.service';
import * as jwt from 'jsonwebtoken';
import axios from 'axios';
import { CognitoPayload } from '../aws/cognito/cognito.interface';

@Injectable()
export class AuthService {
  constructor(
    private readonly configService: ConfigService,
    private readonly cognitoService: CognitoService,
  ) {}

  private generateJwtToken(user: CognitoPayload) {
    if (!process.env.JWT_SECRET) {
      throw new Error('JWT_SECRET is not defined in environment variables.');
    }

    return jwt.sign(user, process.env.JWT_SECRET);
  }
  async exchangeGoogleCodeForTokens(code: string): Promise<any> {
    const clientId = this.configService.get<string>('GOOGLE_CLIENT_ID');
    const clientSecret = this.configService.get<string>('GOOGLE_CLIENT_SECRET');
    const redirectUri = this.configService.get<string>('COGNITO_REDIRECT_URI');

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
    params.append('code', code);
    params.append('client_id', clientId);
    params.append('client_secret', clientSecret);
    params.append('redirect_uri', `${redirectUri}/google`);

    try {
      const response = await axios.post(url, params);
      console.log();
      return response.data;
    } catch (error) {
      throw new Error(`Failed to exchange code for tokens: ${error.message}`);
    }
  }
  async loginWithGoogle(googleCode: string): Promise<any> {
    try {
      const tokenResponse = await this.exchangeGoogleCodeForTokens(googleCode);
    } catch (error) {
      throw new Error(`Google OAuth login failed: ${error.message}`);
    }
  }
  async login(email: string, password: string) {
    try {
      const authResult = await this.cognitoService.authenticateUser(
        email,
        password,
      );

      if (
        !authResult ||
        !authResult.AuthenticationResult ||
        !authResult.AuthenticationResult.AccessToken
      ) {
        throw new Error('Authentication failed or invalid credentials');
      }

      const userInfo: CognitoPayload =
        await this.cognitoService.getUserInfo(email);

      const token = this.generateJwtToken(userInfo);

      return { user: userInfo, token };
    } catch (error) {
      throw new Error(`Login failed: ${error.message}`);
    }
  }
}
