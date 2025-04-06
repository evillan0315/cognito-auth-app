import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { CognitoService } from '../aws/cognito/cognito.service'; // Import CognitoService
import {
  AdminCreateUserCommand,
  AdminUpdateUserAttributesCommand,
  AdminDeleteUserCommand,
  AdminAddUserToGroupCommand,
  AdminRemoveUserFromGroupCommand,
  ListUsersCommand,
  ListUsersCommandOutput,
} from '@aws-sdk/client-cognito-identity-provider';
import { CreateUserDto, UpdateUserDto, UserDto } from './dto';
import { User } from './user.interface'; // Use User interface

@Injectable()
export class UserService {
  constructor(
    private readonly cognitoService: CognitoService, // Inject CognitoService
  ) {}
}
