import { Controller, Post, Body, UseGuards } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiQuery,
  ApiBody,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { PrismaService } from './prisma.service';
import { PrismaOperationDto } from './dto/prisma-operation.dto';

import { Roles } from '../admin/roles/roles.decorator'; // Ensure correct path
import { Role } from '../admin/roles/role.enum'; // Ensure correct path
import { RolesGuard } from '../admin/roles/roles.guard'; // Ensure correct path
import { CognitoGuard } from '../aws/cognito/cognito.guard'; // Adjust the path as needed
@ApiTags('Prisma') // Updated Swagger grouping
@ApiBearerAuth() // Requires authentication via Bearer token
@UseGuards(CognitoGuard, RolesGuard)
@Controller('api/prisma')
export class PrismaController {
  constructor(private readonly prismaService: PrismaService) {}

  @Post()
  @Roles(Role.ADMIN, Role.SUPERADMIN) // Restrict to Admins
  @ApiOperation({ summary: 'Execute a dynamic Prisma operation' })
  @ApiResponse({ status: 200, description: 'Operation executed successfully.' })
  async executeOperation(@Body() body: PrismaOperationDto) {
    return this.prismaService.handler(body.model, body.operation, body.data);
  }
}
