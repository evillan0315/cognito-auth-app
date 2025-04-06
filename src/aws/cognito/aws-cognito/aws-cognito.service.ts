import { Injectable } from '@nestjs/common';
import {
  CognitoIdentityProviderClient,
  GetUserCommand,
} from '@aws-sdk/client-cognito-identity-provider';

@Injectable()
export class AwsCognitoService {}
