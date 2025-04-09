import { Injectable } from '@nestjs/common';
import { CanActivate, ExecutionContext } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class CognitoGuard extends AuthGuard('cognito') {
  canActivate(context: ExecutionContext) {
    return super.canActivate(context);
  }
}
