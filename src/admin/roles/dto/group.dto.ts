import { IsString, IsOptional } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class AddUserToGroupDto {
  @ApiProperty({
    example: 'john_doe',
    description: 'The username of the Cognito user',
  })
  @IsString()
  username: string;

  @ApiProperty({
    example: 'admin',
    description: 'The name of the group to add the user to',
  })
  @IsString()
  groupName: string;
}

export class RemoveUserFromGroupDto {
  @ApiProperty({
    description: 'The username of the user to remove',
    example: 'johndoe',
  })
  @IsString()
  username: string;

  @ApiProperty({
    description: 'The name of the group to remove the user from',
    example: 'admin',
  })
  @IsString()
  groupName: string;
}

export class CreateGroupDto {
  @ApiProperty({ example: 'admin', description: 'The name of the group' })
  @IsString()
  groupName: string;

  @ApiProperty({
    example: 'Group for admin users',
    description: 'Description of the group',
  })
  @IsString()
  @IsOptional()
  description?: string;

  @ApiProperty({
    example: 'arn:aws:iam::123456789012:role/AdminRole',
    description: 'The IAM Role ARN to assign to the group',
  })
  @IsString()
  @IsOptional()
  roleArn?: string;
}

export class DeleteGroupDto {
  @ApiProperty({
    description: 'The name of the group to delete',
    example: 'admin',
  })
  @IsString()
  groupName: string;
}
