import { Controller, Get, UseGuards, Post, Body } from '@nestjs/common';
import { RolesService } from './roles.service';
import {
  ApiTags,
  ApiOperation,
  ApiBearerAuth,
  ApiResponse,
  ApiBody,
} from '@nestjs/swagger';
import { RolesGuard } from './roles.guard'; // adjust path as needed
import { CognitoGuard } from '../../aws/cognito/cognito.guard'; // adjust path as needed
import { Roles } from './roles.decorator'; // adjust path as needed
import { Role } from './role.enum'; // adjust path as needed
import {
  AddUserToGroupDto,
  CreateGroupDto,
  RemoveUserFromGroupDto,
  DeleteGroupDto,
} from './dto/group.dto';

@ApiTags('Admin - Roles')
@ApiBearerAuth()
@Controller('api/admin/roles')
@UseGuards(CognitoGuard, RolesGuard)
export class RolesController {
  constructor(private readonly rolesService: RolesService) {}
  @Get('groups')
  @Roles(Role.ADMIN, Role.SUPERADMIN)
  @ApiOperation({ summary: 'List all Cognito user groups (Admin only)' })
  @ApiResponse({
    status: 200,
    description: 'Successfully retrieved list of Cognito groups.',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden. Insufficient role privileges.',
  })
  @ApiResponse({
    status: 500,
    description: 'Failed to retrieve groups from Cognito.',
  })
  async listGroups() {
    return this.rolesService.listGroups();
  }
  @Post('add/user')
  @Roles(Role.ADMIN, Role.SUPERADMIN)
  @ApiOperation({ summary: 'Add user to a Cognito group  (Admin only)' })
  @ApiResponse({
    status: 201,
    description: 'User added to group successfully.',
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid request body or Cognito error.',
  })
  @ApiBody({ type: AddUserToGroupDto })
  async addUserToGroup(
    @Body() body: AddUserToGroupDto,
  ): Promise<{ message: string }> {
    await this.rolesService.addUserToGroup(body.username, body.groupName);
    return {
      message: `User ${body.username} added to group ${body.groupName}`,
    };
  }
  @Post('remove/user')
  @Roles(Role.ADMIN, Role.SUPERADMIN)
  @ApiOperation({ summary: 'Remove a user from a Cognito group  (Admin only)' })
  @ApiResponse({
    status: 200,
    description: 'User removed from group successfully.',
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid request body or Cognito error.',
  })
  @ApiBody({ type: RemoveUserFromGroupDto })
  async removeUserFromGroup(
    @Body() body: RemoveUserFromGroupDto,
  ): Promise<{ message: string }> {
    await this.rolesService.removeUserFromGroup(body.username, body.groupName);
    return {
      message: `User ${body.username} removed from group ${body.groupName}`,
    };
  }
  @Post('create/group')
  @Roles(Role.ADMIN, Role.SUPERADMIN)
  @ApiOperation({ summary: 'Create a new Cognito user group  (Admin only)' })
  @ApiResponse({ status: 201, description: 'Group created successfully.' })
  @ApiResponse({
    status: 400,
    description: 'Invalid request body or Cognito error.',
  })
  @ApiBody({ type: CreateGroupDto })
  async createGroup(
    @Body() body: CreateGroupDto,
  ): Promise<{ message: string }> {
    const description = body.description || ''; // Default to an empty string if undefined
    const roleArn = body.roleArn || ''; // You can specify the IAM Role ARN here, or it can be optional.

    try {
      await this.rolesService.createGroup(body.groupName, roleArn, description);
      return { message: `Group ${body.groupName} created successfully` };
    } catch (error) {
      throw error;
    }
  }
  @Post('delete/group')
  @Roles(Role.ADMIN, Role.SUPERADMIN)
  @ApiOperation({ summary: 'Delete a Cognito group  (Admin only)' })
  @ApiResponse({ status: 200, description: 'Group deleted successfully.' })
  @ApiResponse({
    status: 400,
    description: 'Invalid request body or Cognito error.',
  })
  @ApiBody({ type: DeleteGroupDto })
  async deleteGroup(
    @Body() body: DeleteGroupDto,
  ): Promise<{ message: string }> {
    await this.rolesService.deleteGroup(body.groupName);
    return { message: `Group ${body.groupName} deleted successfully` };
  }
}
