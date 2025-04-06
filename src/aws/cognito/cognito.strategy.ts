import { PassportStrategy } from '@nestjs/passport';
import { Strategy, ExtractJwt } from 'passport-jwt';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as jwksClient from 'jwks-rsa';
import { CognitoService } from './cognito.service';
import { CognitoPayload } from './cognito.interface';
import * as jwt from 'jsonwebtoken';

@Injectable()
export class CognitoStrategy extends PassportStrategy(Strategy, 'cognito') {
  private jwksClient: jwksClient.JwksClient;

  constructor(private readonly cognitoService: CognitoService) {
    super({
      //jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      jwtFromRequest: (req) => {
        console.log('Incoming Headers jwtFromRequest:', req.headers);
        console.log('Incoming Headers jwtFromRequest cookies:', req.cookies);
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
          console.log('Extracted JWT:', authHeader.split(' ')[1]);
          return authHeader.split(' ')[1];
        }

        if (req && req.cookies) {
          console.log('JWT from Cookies:', req.cookies['access_token']);
          return req.cookies['access_token'];
        }

        console.warn('No JWT Found in Headers or Cookies');
        return null;
      },
      secretOrKeyProvider: async (request, rawJwtToken, done) => {
        try {
          this.jwksClient = jwksClient({
            jwksUri: `https://cognito-idp.${process.env.AWS_REGION}.amazonaws.com/${process.env.COGNITO_USER_POOL_ID}/.well-known/jwks.json`,
          });

          const decodedToken = jwt.decode(rawJwtToken, { complete: true });
          if (!decodedToken || !decodedToken.header.kid) {
            return done('Unable to extract key ID', null);
          }

          const key = await this.jwksClient.getSigningKey(
            decodedToken.header.kid,
          );
          const signingKey = key.getPublicKey();
          done(null, signingKey);
        } catch (error) {
          done(error, null);
        }
      },
      issuer: `https://cognito-idp.${process.env.AWS_REGION}.amazonaws.com/${process.env.COGNITO_USER_POOL_ID}`,
    });
  }

  async validate(payload: any): Promise<any> {
    console.log(payload, 'CognitoStrategy payload');
    // Use client_id if token is access token
    const expectedAudience = process.env.COGNITO_CLIENT_ID;

    if (payload.client_id !== expectedAudience) {
      throw new UnauthorizedException('Invalid client_id in access token');
    }
    const user = await this.cognitoService.getUserInfo(payload.username);
    if (!user) {
      throw new Error('User not found');
    }

    return user;
  }
}
