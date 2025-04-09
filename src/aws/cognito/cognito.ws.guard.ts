// src/auth/guards/cognito-ws.guard.ts
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Socket } from 'socket.io';
import * as jwt from 'jsonwebtoken';
import * as jwksClient from 'jwks-rsa';
import { CognitoService } from './cognito.service';
import * as cookie from 'cookie';
@Injectable()
export class CognitoWsGuard implements CanActivate {
  private jwksClient: jwksClient.JwksClient;

  constructor(
    private readonly cognitoService: CognitoService,
    private readonly reflector: Reflector,
  ) {
    this.jwksClient = jwksClient({
      jwksUri: `https://cognito-idp.${process.env.AWS_REGION}.amazonaws.com/${process.env.COGNITO_USER_POOL_ID}/.well-known/jwks.json`,
    });
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const client: Socket = context.switchToWs().getClient<Socket>();

    //console.log(client.handshake, 'CognitoWsGuard canActivate');
    // Get the cookies from the handshake headers
    const cookies = client.handshake?.headers?.cookie;
    if (!cookies) {
      throw new UnauthorizedException('Missing cookies');
    }
    const parsedCookies = cookie.parse(cookies);
    let token = parsedCookies['access_token'];

    // If no token found in header, check for the token in the cookies
    if (!token) {
      token =
        client.handshake?.auth?.token ||
        client.handshake?.headers?.authorization?.split(' ')[1];
    }
    if (!token) {
      throw new UnauthorizedException('Missing Cognito token');
    }

    try {
      // const decoded = jwt.decode(token, { complete: true }) as any;
      let decodedToken;
      //console.log(token, 'token CognitoWsGuard');
      if (!process.env.JWT_SECRET) {
        throw new UnauthorizedException('JWT_SECRET not found');
      }
      decodedToken = jwt.verify(token, process.env.JWT_SECRET); // Use JWT_SECRET for verification
      //console.log(decodedToken, 'decodedToken verified');d
      const user = await this.cognitoService.getUserInfo(decodedToken.username);
      if (!user) throw new UnauthorizedException('User not found');

      // Attach user to client for later use
      //(client as any).user = user;
      // Attach user info to socket for access in gateway
      client.data.user = user;

      return true;
    } catch (err) {
      console.error('[CognitoWsGuard] Token error:', err);
      throw new UnauthorizedException('Invalid Cognito token');
    }
  }
}
