import { Controller, Get, Post, Body, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { PostgresService } from './postgres.service';
import { RdsBackupService } from './rds-backup.service';
import { RdsParameterService } from './rds-parameter.service';
import { CognitoGuard } from '../../aws/cognito/cognito.guard';
import { RolesGuard } from '../../admin/roles/roles.guard';
import { Roles } from '../../admin/roles/roles.decorator';
import { Role } from '../../admin/roles/role.enum';

@ApiTags('AWS RDS PostgreSQL')
@Controller('api/rds')
@UseGuards(CognitoGuard, RolesGuard)
@ApiBearerAuth()
export class PostgresController {
  constructor(
    private readonly postgresService: PostgresService,
    private readonly rdsBackupService: RdsBackupService,
    private readonly rdsParameterService: RdsParameterService,
  ) {}

  @Get('health')
  @ApiOperation({ summary: 'Check RDS database health' })
  async checkHealth() {
    const isHealthy = await this.postgresService.checkHealth();

    return {
      status: isHealthy ? 'ok' : 'error',
      message: isHealthy
        ? 'RDS connection is healthy'
        : 'RDS connection failed',
    };
  }

  @Get('stats')
  @ApiOperation({ summary: 'Get RDS database statistics' })
  @Roles(Role.ADMIN, Role.SUPERADMIN)
  async getDatabaseStats() {
    return this.postgresService.getDatabaseStats();
  }

  @Get('info')
  @ApiOperation({ summary: 'Get RDS instance information' })
  @Roles(Role.ADMIN, Role.SUPERADMIN)
  async getRdsInfo() {
    return this.postgresService.getRdsInstanceInfo();
  }

  @Get('slow-queries')
  @ApiOperation({ summary: 'Get slow queries' })
  @Roles(Role.ADMIN, Role.SUPERADMIN)
  async getSlowQueries() {
    return this.postgresService.getSlowQueries();
  }

  @Get('connection-pool')
  @ApiOperation({ summary: 'Get connection pool statistics' })
  @Roles(Role.ADMIN, Role.SUPERADMIN)
  async getConnectionPoolStats() {
    return this.postgresService.getConnectionPoolStats();
  }

  @Get('snapshots')
  @ApiOperation({ summary: 'List database snapshots' })
  @Roles(Role.ADMIN, Role.SUPERADMIN)
  async listSnapshots() {
    return this.rdsBackupService.listSnapshots();
  }

  @Post('snapshots')
  @ApiOperation({ summary: 'Create a database snapshot' })
  @Roles(Role.ADMIN, Role.SUPERADMIN)
  async createSnapshot(@Body() body: { snapshotId: string }) {
    return this.rdsBackupService.createSnapshot(body.snapshotId);
  }

  @Get('parameters')
  @ApiOperation({ summary: 'Get RDS parameter group settings' })
  @Roles(Role.ADMIN, Role.SUPERADMIN)
  async getParameterGroupSettings() {
    return this.rdsParameterService.getParameterGroupSettings();
  }

  @Post('parameters')
  @ApiOperation({ summary: 'Update RDS parameter group settings' })
  @Roles(Role.ADMIN, Role.SUPERADMIN)
  async updateParameterGroupSettings(
    @Body() body: { parameters: Array<{ name: string; value: string }> },
  ) {
    return this.rdsParameterService.updateParameterGroupSettings(
      body.parameters,
    );
  }
}
