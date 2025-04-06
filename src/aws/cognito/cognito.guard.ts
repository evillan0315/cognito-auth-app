import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class CognitoGuard extends AuthGuard('cognito') {
  handleRequest(err, user, info, context, status) {
    const req = context.switchToHttp().getRequest();
    if (err || !user) {
      throw err || new UnauthorizedException();
    }
    return user;
  }
}
