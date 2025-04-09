// src/auth/cognito.strategy.ts

import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-jwt';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { CognitoService } from './cognito.service';
import { CreateUserDto } from '../../user/dto';
import * as jwt from 'jsonwebtoken';
import axios from 'axios';

@Injectable()
export class CognitoStrategy extends PassportStrategy(Strategy, 'cognito') {
  constructor(private readonly cognitoService: CognitoService) {
    super({
      jwtFromRequest: (req) => {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
          return authHeader.split(' ')[1];
        }

        if (req && req.cookies) {
          return req.cookies['access_token'];
        }

        console.warn('No JWT Found in Headers or Cookies');
        return null;
      },
      secretOrKey: process.env.JWT_SECRET, // Use JWT_SECRET for verifying JWT
    });
  }

  async validate(
    payload: any,
    refreshToken: any,
    profile: any,
    done: VerifyCallback,
  ): Promise<any> {
    // Validate issuer and audience
    const expectedIssuer = `https://cognito-idp.${process.env.AWS_REGION}.amazonaws.com/${process.env.COGNITO_USER_POOL_ID}`;
    const expectedAudience = process.env.COGNITO_CLIENT_ID;
    // Verify GitHub access token using JWT_SECRET
    let token;

    if (!process.env.JWT_SECRET) {
      throw new UnauthorizedException('JWT_SECRET not found');
    }

    if (!payload) throw new UnauthorizedException('Payload not found');
    //token = jwt.sign(payload, process.env.JWT_SECRET); // Use JWT_SECRET for verification
    if (payload?.iss === 'github') {
      if (!payload.email) {
        throw new Error('No email found in GitHub profile');
      }

      // Check if the user already exists in Cognito
      let userRes = await this.cognitoService.getUserInfoByEmail(payload.email);

      if (!userRes) {
        const createUser: CreateUserDto = {
          username: payload.email,
          email: payload.email,
          name: payload.email,
          role: 'user',
          groups: ['user'],
        };

        const userCreated = await this.cognitoService.createUser(createUser);

        if (!userCreated) {
          throw new Error('User not created');
        }

        userRes = userCreated; // Use the newly created user
      }

      const user = await this.cognitoService.getUserInfo(userRes.Username);

      // Return the user with relevant data
      return user;
    } else if (payload?.iss === 'google') {
      if (!payload.email) {
        throw new Error('No email found in GitHub profile');
      }

      // Check if the user already exists in Cognito
      let userRes = await this.cognitoService.getUserInfoByEmail(payload.email);

      if (!userRes) {
        const createUser: CreateUserDto = {
          username: payload.email,
          email: payload.email,
          name: payload.email,
          role: 'user',
          groups: ['user'],
        };

        const userCreated = await this.cognitoService.createUser(createUser);

        if (!userCreated) {
          throw new Error('User not created');
        }

        userRes = userCreated; // Use the newly created user
      }

      const user = await this.cognitoService.getUserInfo(userRes.Username);

      // Return the user with relevant data
      return user;
    } else if (payload?.iss === 'credentials') {
      const user = await this.cognitoService.getUserInfo(payload.username);
      return user;
    } else {
      return payload;
    }
  }
}
