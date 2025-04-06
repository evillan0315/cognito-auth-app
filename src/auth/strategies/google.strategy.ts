import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';
import { Injectable } from '@nestjs/common';
import { CognitoService } from '../../aws/cognito/cognito.service';
import { CreateUserDto } from '../../user/dto';
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
    console.log('Access Token:', accessToken);
    console.log('Profile:', profile);

    const { displayName, emails, photos, _json } = profile;

    if (!emails || emails.length === 0) {
      return done(new Error('No email found in Google profile'), false);
    }
    const userRes = await this.cognitoService.getUserInfoByEmail(
      emails[0].value,
    );
    if (!userRes) {
      const createUser: CreateUserDto = {
        username: emails[0].value,
        email: emails[0].value,
        name: displayName,
        role: 'user',
        groups: ['user'],
        //"image": photos[0].value
      };
      console.log(createUser, 'createUser');
      const userCreated = await this.cognitoService.createUser(createUser);
      if (!userCreated) {
        throw new Error('User not created');
      }
      done(null, userCreated);
    }
    const user = await this.cognitoService.getUserInfo(userRes.Username);

    if (!user) {
      throw new Error('User not found');
    }
    //return user;

    // Pass the user information to the callback
    done(null, user);
  }
}
