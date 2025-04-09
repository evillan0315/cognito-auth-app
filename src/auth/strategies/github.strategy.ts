// src/auth/github.strategy.ts

import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy as GitHubStrategy, VerifyCallback } from 'passport-github';
import axios from 'axios'; // We'll use axios to call GitHub's API

import { CognitoService } from '../../aws/cognito/cognito.service';
import { CreateUserDto } from '../../user/dto';
import * as jwt from 'jsonwebtoken'; // For verifying the JWT

@Injectable()
export class GithubStrategy extends PassportStrategy(GitHubStrategy, 'github') {
  constructor(private readonly cognitoService: CognitoService) {
    super({
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: `${process.env.COGNITO_REDIRECT_URI}/github`,
      scope: ['user:email'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<any> {
    // Check the user's email from the profile or GitHub API
    const { emails, displayName, login } = profile;

    if (!emails[0].value) {
      throw new Error('No email found in GitHub profile');
    }

    // Check if the user already exists in Cognito
    let userRes = await this.cognitoService.getUserInfoByEmail(emails[0].value);

    if (!userRes) {
      const createUser: CreateUserDto = {
        username: emails[0].value,
        email: emails[0].value,
        name: displayName || login,
        role: 'user',
        groups: ['user'],
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
