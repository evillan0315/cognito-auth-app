import { Controller, Get, Post, Param, Body, UseGuards } from '@nestjs/common';
import { Ec2Service } from './ec2.service';
import { LaunchInstanceDto } from './launch-instance.dto';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { Roles } from '../admin/roles/roles.decorator'; // Ensure correct path
import { Role } from '../admin/roles/role.enum'; // Ensure correct path
import { RolesGuard } from '../admin/roles/roles.guard'; // Ensure correct path
import { CognitoGuard } from '../aws/cognito/cognito.guard'; // Adjust the path as needed

@ApiTags('EC2') // Updated Swagger grouping
@ApiBearerAuth() // Requires authentication via Bearer token
@UseGuards(CognitoGuard, RolesGuard)
@Controller('ec2')
export class Ec2Controller {
  constructor(private readonly ec2Service: Ec2Service) {}

  @Get()
  @Roles(Role.ADMIN, Role.SUPERADMIN) // Restrict to Admins
  @ApiOperation({ summary: 'List all EC2 instances' })
  list() {
    return this.ec2Service.listInstances();
  }

  @Post('start/:id')
  @Roles(Role.ADMIN, Role.SUPERADMIN) // Restrict to Admins
  @ApiOperation({ summary: 'Start an EC2 instance' })
  start(@Param('id') id: string) {
    return this.ec2Service.startInstance(id);
  }

  @Post('stop/:id')
  @Roles(Role.ADMIN, Role.SUPERADMIN) // Restrict to Admins
  @ApiOperation({ summary: 'Stop an EC2 instance' })
  stop(@Param('id') id: string) {
    return this.ec2Service.stopInstance(id);
  }

  @Post('terminate/:id')
  @Roles(Role.ADMIN, Role.SUPERADMIN) // Restrict to Admins
  @ApiOperation({ summary: 'Terminate an EC2 instance' })
  terminate(@Param('id') id: string) {
    return this.ec2Service.terminateInstance(id);
  }

  @Post('launch')
  @Roles(Role.ADMIN, Role.SUPERADMIN) // Restrict to Admins
  @ApiOperation({ summary: 'Launch a new EC2 instance' })
  launch(@Body() dto: LaunchInstanceDto) {
    return this.ec2Service.launchInstance(dto);
  }
}
