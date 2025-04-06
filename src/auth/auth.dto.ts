import { ApiProperty } from '@nestjs/swagger';

export class AuthSignUpDto {
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com',
  })
  email: string;

  @ApiProperty({ description: 'User password', example: 'securepassword123' })
  password: string;

  @ApiProperty({ description: 'User name', example: 'John Doe' })
  name: string;
}

export class AuthSignInDto {
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com',
  })
  email: string;

  @ApiProperty({ description: 'User password', example: 'securepassword123' })
  password: string;
}

export class RefreshTokenDto {
  refreshToken: string;
}

export class ValidateTokenDto {
  @ApiProperty({
    description: 'The JWT token to be validated',
    example: 'your-jwt-token',
  })
  token: string;
}
export class GetProfileDto {
  @ApiProperty({
    description: 'Access token used to retrieve user profile',
    example: 'eyJraWQ6...access-token',
  })
  accessToken: string;
}
