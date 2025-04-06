import { Controller, Get, UseGuards, Request } from '@nestjs/common';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
} from '@nestjs/swagger';
import { Roles } from './roles/roles.decorator'; // Adjust path if needed
import { RolesGuard } from './roles/roles.guard'; // Adjust path if needed
import { CognitoGuard } from '../aws/cognito/cognito.guard'; // Adjust the path as needed
import { Role } from './roles/role.enum'; // Adjust path if needed

@ApiTags('Admin')
@ApiBearerAuth() // Assumes JWT authentication is required
@Controller('api/admin')
@UseGuards(CognitoGuard, RolesGuard)
export class AdminController {
  /*@Get('dashboard')
  @Roles(Role.ADMIN, Role.SUPERADMIN)
  @ApiOperation({ summary: 'Access admin dashboard' })
  @ApiResponse({ status: 200, description: 'Successfully retrieved the admin dashboard.' })
  @ApiResponse({ status: 403, description: 'Forbidden. Insufficient role privileges.' })
  getDashboard(@Request() req) {
    return { message: 'Welcome to the Admin Dashboard', user: req.user };
  }

  @Get('my-dashboard')
  @Roles(Role.USER, Role.ADMIN, Role.SUPERADMIN) 
  @ApiOperation({ summary: 'Access user dashboard' })
  @ApiResponse({ status: 200, description: 'Successfully retrieved profile.' })
  @ApiResponse({ status: 403, description: 'Forbidden. Insufficient role privileges.' })
  getMyDashboard(@Request() req) {
    return { message: 'Welcome to the My Dashboard', user: req.user };
  }*/
}
