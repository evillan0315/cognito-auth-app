import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Delete,
  Put,
  UseGuards,
} from '@nestjs/common';
import { UserService } from './user.service'; // Adjusted path
import { CreateUserDto, UpdateUserDto } from './dto';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiParam,
} from '@nestjs/swagger';
import { User } from './user.entity'; // Ensure correct path

import { CognitoService } from '../aws/cognito/cognito.service';
import { Roles } from '../admin/roles/roles.decorator'; // Ensure correct path
import { Role } from '../admin/roles/role.enum'; // Ensure correct path
import { RolesGuard } from '../admin/roles/roles.guard'; // Ensure correct path
import { CognitoGuard } from '../aws/cognito/cognito.guard'; // Adjust the path as needed
@ApiTags('Admin - Users') // Updated Swagger grouping
@ApiBearerAuth() // Requires authentication via Bearer token
@UseGuards(CognitoGuard, RolesGuard)
@Controller('api/users') // Nested inside admin
export class UserController {
  constructor(private readonly cognitoService: CognitoService) {} // Inject CognitoService

  @Post()
  @Roles(Role.ADMIN, Role.SUPERADMIN) // Restrict to Admins
  @ApiOperation({ summary: 'Create a new user (admin only)' })
  @ApiResponse({
    status: 201,
    description: 'User created successfully.',
    type: User,
  })
  @ApiResponse({ status: 400, description: 'Invalid input data.' })
  async create(@Body() createUserDto: CreateUserDto) {
    try {
      const result = await this.cognitoService.createUser(createUserDto); // Using CognitoService to create a user
      return result;
    } catch (error) {
      throw error;
    }
  }

  @Get()
  @Roles(Role.ADMIN, Role.SUPERADMIN) // Restrict to Admins
  @ApiOperation({ summary: 'Retrieve all users (admin only)' })
  @ApiResponse({ status: 200, description: 'List of users.', type: [User] })
  async findAll() {
    try {
      const users = await this.cognitoService.listUsers(); // Using CognitoService to find all users
      return users;
    } catch (error) {
      throw error;
    }
  }

  @Get(':username') // Use username for parameter
  @Roles(Role.ADMIN) // Restrict to Admins
  @ApiOperation({ summary: 'Retrieve user details by username (admin only)' })
  @ApiParam({ name: 'username', description: 'Username of the user' }) // Correct the param name here
  @ApiResponse({
    status: 200,
    description: 'User retrieved successfully.',
    type: User,
  })
  @ApiResponse({ status: 404, description: 'User not found.' })
  async findOne(@Param('username') username: string) {
    // Correct parameter usage
    try {
      const user = await this.cognitoService.getUserInfo(username); // Using UserService to find user by username
      return user;
    } catch (error) {
      throw error;
    }
  }

  @Put(':username')
  @Roles(Role.ADMIN, Role.SUPERADMIN) // Restrict to Admins
  @ApiOperation({ summary: 'Update user details by username (admin only)' })
  @ApiParam({ name: 'username', description: 'Username of the user' }) // Correct the param name here
  @ApiResponse({
    status: 200,
    description: 'User updated successfully.',
    type: User,
  })
  @ApiResponse({ status: 404, description: 'User not found.' })
  async update(
    @Param('username') username: string,
    @Body() updateUserDto: UpdateUserDto,
  ) {
    try {
      // Pass the whole DTO to the service instead of extracting the attributes manually
      const updatedUser = await this.cognitoService.updateUser(
        username,
        updateUserDto,
      );
      return updatedUser;
    } catch (error) {
      throw error;
    }
  }

  @Delete(':username') // Use username for parameter
  @Roles(Role.ADMIN, Role.SUPERADMIN) // Restrict to Admins
  @ApiOperation({ summary: 'Delete user by username (admin only)' })
  @ApiParam({ name: 'username', description: 'Username of the user' }) // Correct the param name here
  @ApiResponse({ status: 200, description: 'User deleted successfully.' })
  @ApiResponse({ status: 404, description: 'User not found.' })
  async remove(@Param('username') username: string) {
    // Correct parameter usage
    try {
      await this.cognitoService.deleteUser(username); // Using UserService to delete user
      return { message: 'User deleted successfully' };
    } catch (error) {
      throw error;
    }
  }
}
