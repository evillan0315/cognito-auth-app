import {
  IsString,
  IsOptional,
  IsEmail,
  IsArray,
  IsBoolean,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateUserDto {
  @ApiProperty({
    description: "The user's username in Cognito",
    example: 'john_doe',
  })
  @IsString()
  username: string; // User's username in Cognito

  @ApiProperty({
    description: "The user's email address",
    example: 'john_doe@example.com',
  })
  @IsEmail()
  email: string; // User's email address

  @ApiProperty({ description: "The user's name", example: 'John Doe' })
  @IsString()
  name: string; // User's name

  @ApiProperty({
    description: "The user's role (optional, default to 'user')",
    example: 'user',
    required: false,
  })
  @IsString()
  @IsOptional()
  role: string; // User's role (optional, default to 'user')

  @ApiProperty({
    description: 'List of groups the user belongs to (optional)',
    example: ['admin', 'developer'],
    required: false,
  })
  @IsArray()
  @IsOptional()
  groups?: string[]; // List of groups the user belongs to (optional)
  @ApiProperty({
    description: "The user's profile image URL (optional)",
    example: 'https://example.com/profile.jpg',
    required: false,
  })
  @IsString()
  @IsOptional()
  image?: string;
}

export class UpdateUserDto {
  @ApiProperty({
    description: "The user's email address (optional)",
    example: 'john_updated@example.com',
    required: false,
  })
  @IsEmail()
  @IsOptional()
  email?: string; // User's email address (optional)

  @ApiProperty({
    description: "The user's name (optional)",
    example: 'John Updated',
    required: false,
  })
  @IsString()
  @IsOptional()
  name?: string; // User's name (optional)

  @ApiProperty({
    description: "The user's role (optional)",
    example: 'admin',
    required: false,
  })
  @IsString()
  @IsOptional()
  role?: string; // User's role (optional)

  @ApiProperty({
    description: 'List of groups the user belongs to (optional)',
    example: ['superadmin'],
    required: false,
  })
  @IsArray()
  @IsOptional()
  groups?: string[]; // List of groups the user belongs to (optional)

  @ApiProperty({
    description: 'Email verified status (optional)',
    example: true,
    required: false,
  })
  @IsBoolean()
  @IsOptional()
  email_verified?: boolean; // Optional email verification status
}

export class UserPrismaDto {
  @ApiProperty({
    description: 'The unique identifier of the user',
    type: String,
  })
  id: string;

  @ApiProperty({
    description: 'The email address of the user',
    type: String,
  })
  email: string;

  @ApiProperty({
    description: 'The name of the user',
    type: String,
    required: false,
  })
  name?: string;

  @ApiProperty({
    description: 'The phone number of the user',
    type: String,
    required: false,
  })
  phone_number?: string;

  @ApiProperty({
    description: 'The address of the user',
    type: String,
    required: false,
  })
  address?: string;

  @ApiProperty({
    description: 'The gender of the user',
    type: String,
    required: false,
  })
  gender?: string;

  @ApiProperty({
    description: 'The username of the user (must be unique)',
    type: String,
    required: false,
  })
  username?: string;

  @ApiProperty({
    description: 'The timestamp when the user was created',
    type: String,
  })
  createdAt: string;
}
export class UserDto {
  @ApiProperty({ description: 'The Cognito user ID', example: 'sub-1234' })
  @IsString()
  sub: string; // The Cognito user ID

  @ApiProperty({
    description: "The user's email address",
    example: 'john_doe@example.com',
  })
  @IsEmail()
  email: string; // User's email address

  @ApiProperty({ description: "The user's name", example: 'John Doe' })
  @IsString()
  name: string; // User's name

  @ApiProperty({ description: "The user's role", example: 'admin' })
  @IsString()
  role: string; // User's role (use Role enum or similar)

  @ApiProperty({
    description: 'Access token used for making API requests',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    required: false,
  })
  @IsOptional()
  @IsString()
  accessToken?: string; // Access token used for making API requests

  @ApiProperty({
    description: 'List of custom attributes for the user',
    type: [Object],
    example: [{ Name: 'custom:role', Value: 'admin' }],
  })
  @IsArray()
  Attributes: {
    Name: string; // Attribute name
    Value: string; // Attribute value
  }[];

  @ApiProperty({
    description: "The user's Cognito Username",
    example: 'john_doe',
  })
  @IsString()
  username: string; // Cognito Username

  @ApiProperty({
    description: 'Audience claim (optional, should match the client ID)',
    example: 'client-id-123',
    required: false,
  })
  @IsOptional()
  @IsString()
  client_id?: string; // Audience claim (optional)

  @ApiProperty({
    description: 'List of group names the user is part of',
    example: ['admin', 'developer'],
  })
  @IsArray()
  groups: string[]; // List of group names the user is part of
}
