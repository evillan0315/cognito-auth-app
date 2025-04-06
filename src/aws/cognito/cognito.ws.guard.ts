// src/auth/guards/cognito-ws.guard.ts
import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Socket } from 'socket.io';
import * as jwt from 'jsonwebtoken';
import * as jwksClient from 'jwks-rsa';
import { CognitoService } from './cognito.service';

@Injectable()
export class CognitoWsGuard implements CanActivate {
  private jwksClient: jwksClient.JwksClient;

  constructor(
    private readonly cognitoService: CognitoService,
    private readonly reflector: Reflector
  ) {
    this.jwksClient = jwksClient({
      jwksUri: `https://cognito-idp.${process.env.AWS_REGION}.amazonaws.com/${process.env.COGNITO_USER_POOL_ID}/.well-known/jwks.json`,
    });
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const client: Socket = context.switchToWs().getClient<Socket>();
    const token = client.handshake?.auth?.token || client.handshake?.headers?.authorization?.split(' ')[1];

    if (!token) {
      throw new UnauthorizedException('Missing Cognito token');
    }

    try {
      const decoded = jwt.decode(token, { complete: true }) as any;

      if (!decoded?.header?.kid) {
        throw new UnauthorizedException('Token missing kid');
      }

      const key = await this.jwksClient.getSigningKey(decoded.header.kid);
      const signingKey = key.getPublicKey();

      const payload = jwt.verify(token, signingKey, {
        issuer: `https://cognito-idp.${process.env.AWS_REGION}.amazonaws.com/${process.env.COGNITO_USER_POOL_ID}`,
      }) as any;

      if (payload.client_id !== process.env.COGNITO_CLIENT_ID) {
        throw new UnauthorizedException('Invalid client_id in token');
      }

      const user = await this.cognitoService.getUserInfo(payload.username);
      if (!user) throw new UnauthorizedException('User not found');

      // Attach user to client for later use
      (client as any).user = user;

      return true;
    } catch (err) {
      console.error('[CognitoWsGuard] Token error:', err);
      throw new UnauthorizedException('Invalid Cognito token');
    }
  }
}

