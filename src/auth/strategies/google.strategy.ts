// src/auth/google.strategy.ts

import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { Injectable } from '@nestjs/common';
import { CognitoService } from '../../aws/cognito/cognito.service';
import { CreateUserDto } from '../../user/dto';
import * as jwt from 'jsonwebtoken'; // Importing jwt to verify the access token

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(private readonly cognitoService: CognitoService) {
    super({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.COGNITO_REDIRECT_URI}/google`,
      scope: ['email', 'profile'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<any> {
    const { displayName, emails, photos, _json } = profile;

    if (!emails[0].value) {
      throw new Error('No email found in GitHub profile');
    }

    // Check if the user already exists in Cognito
    let userRes = await this.cognitoService.getUserInfoByEmail(emails[0].value);

    if (!userRes) {
      const createUser: CreateUserDto = {
        username: emails[0].value,
        email: emails[0].value,
        name: displayName,
        role: 'user',
        groups: ['user'],
        // "image": photos[0].value // You can include the image if needed
      };

      const userCreated = await this.cognitoService.createUser(createUser);
      if (!userCreated) {
        return done(new Error('User not created'), false);
      }
      userRes = userCreated; // Use the newly created user
    }

    const user = await this.cognitoService.getUserInfo(userRes.Username);

    if (!user) {
      return done(new Error('User not found'), false);
    }

    // Return the user along with relevant profile and tokens
    return done(null, {
      user,
      profile,
      accessToken,
      refreshToken,
    });
  }
}
