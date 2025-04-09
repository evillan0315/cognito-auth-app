# Module Integration Guide

This guide explains how to integrate the AWS RDS PostgreSQL module into your NestJS application.

## Module Registration

To use the PostgreSQL module in your application, you need to import it in your application module:

```typescript
// app.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { PostgresModule } from './database/postgres/postgres.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),
    PostgresModule,
    // Other modules...
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
```

## Environment Configuration

Create or update your `.env` file with the necessary configuration:

```
# Database URL (primary connection method)
DATABASE_URL=postgresql://username:password@hostname:port/database

# AWS RDS PostgreSQL (fallback connection method)
RDS_HOST=your-rds-endpoint.rds.amazonaws.com
RDS_PORT=5432
RDS_USER=postgres
RDS_PASSWORD=your_secure_password
RDS_DB=your_database_name
RDS_INSTANCE_ID=your-rds-instance-id
RDS_PARAMETER_GROUP=your-parameter-group-name

# AWS Credentials
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key

# Connection Pool Settings
DB_POOL_MAX=20
DB_POOL_MIN=5
DB_POOL_IDLE=10000

# SSL Configuration (for production)
RDS_CA_CERT=your_ca_certificate_content

# Environment
NODE_ENV=development
```

## Using the Services

### Basic Database Operations

```typescript
// users.service.ts
import { Injectable } from '@nestjs/common';
import { PostgresService } from '../database/postgres/postgres.service';

@Injectable()
export class UsersService {
  constructor(private readonly postgresService: PostgresService) {}

  async findAll() {
    return this.postgresService.executeQuery('SELECT * FROM users');
  }

  async findOne(id: number) {
    return this.postgresService.executeQuery('SELECT * FROM users WHERE id = $1', [id]);
  }

  async create(user: { name: string, email: string }) {
    return this.postgresService.executeQuery(
      'INSERT INTO users(name, email) VALUES($1, $2) RETURNING *',
      [user.name, user.email]
    );
  }

  async update(id: number, user: { name?: string, email?: string }) {
    const updates = [];
    const values = [];
    
    if (user.name) {
      updates.push(`name = $${updates.length + 1}`);
      values.push(user.name);
    }
    
    if (user.email) {
      updates.push(`email = $${updates.length + 1}`);
      values.push(user.email);
    }
    
    if (updates.length === 0) {
      return null;
    }
    
    values.push(id);
    
    return this.postgresService.executeQuery(
      `UPDATE users SET ${updates.join(', ')} WHERE id = $${values.length} RETURNING *`,
      values
    );
  }

  async delete(id: number) {
    return this.postgresService.executeQuery(
      'DELETE FROM users WHERE id = $1 RETURNING *',
      [id]
    );
  }
}
```

### Database Health Monitoring

```typescript
// health.service.ts
import { Injectable } from '@nestjs/common';
import { PostgresService } from '../database/postgres/postgres.service';

@Injectable()
export class HealthService {
  constructor(private readonly postgresService: PostgresService) {}

  async checkDatabaseHealth() {
    const isHealthy = await this.postgresService.checkHealth();
    
    return {
      database: {
        status: isHealthy ? 'up' : 'down',
        message: isHealthy ? 'Database connection is healthy' : 'Database connection failed',
      },
    };
  }

  async getDatabaseStats() {
    const stats = await this.postgresService.getDatabaseStats();
    const poolStats = await this.postgresService.getConnectionPoolStats();
    
    return {
      size: stats.databaseSize,
      tables: stats.tables.length,
      connections: poolStats,
    };
  }
}
```

### RDS Instance Management

```typescript
// database-admin.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { RdsInstanceService } from '../database/postgres/rds-instance.service';

@Injectable()
export class DatabaseAdminService {
  private readonly logger = new Logger(DatabaseAdminService.name);
  
  constructor(private readonly rdsInstanceService: RdsInstanceService) {}

  async listInstances() {
    return this.rdsInstanceService.listInstances();
  }

  async createDevelopmentInstance(name: string) {
    this.logger.log(`Creating development database instance: ${name}`);
    
    return this.rdsInstanceService.createInstance({
      dbInstanceIdentifier: name,
      dbInstanceClass: 'db.t3.micro',
      allocatedStorage: 20,
      multiAZ: false,
      tags: [
        { Key: 'Environment', Value: 'Development' },
        { Key: 'Project', Value: 'MyProject' }
      ]
    });
  }

  async createProductionInstance(name: string) {
    this.logger.log(`Creating production database instance: ${name}`);
    
    return this.rdsInstanceService.createInstance({
      dbInstanceIdentifier: name,
      dbInstanceClass: 'db.t3.medium',
      allocatedStorage: 50,
      multiAZ: true,
      tags: [
        { Key: 'Environment', Value: 'Production' },
        { Key: 'Project', Value: 'MyProject' }
      ]
    });
  }

  async stopInstance(instanceId: string) {
    this.logger.log(`Stopping database instance: ${instanceId}`);
    return this.rdsInstanceService.stopInstance(instanceId);
  }

  async startInstance(instanceId: string) {
    this.logger.log(`Starting database instance: ${instanceId}`);
    return this.rdsInstanceService.startInstance(instanceId);
  }

  async deleteInstance(instanceId: string, skipFinalSnapshot: boolean = false) {
    this.logger.log(`Deleting database instance: ${instanceId}`);
    
    return this.rdsInstanceService.deleteInstance({
      dbInstanceIdentifier: instanceId,
      skipFinalSnapshot,
      finalDBSnapshotIdentifier: skipFinalSnapshot ? undefined : `${instanceId}-final-${Date.now()}`
    });
  }

  async scaleUpInstance(instanceId: string) {
    this.logger.log(`Scaling up database instance: ${instanceId}`);
    
    return this.rdsInstanceService.modifyInstance({
      dbInstanceIdentifier: instanceId,
      dbInstanceClass: 'db.t3.large',
      allocatedStorage: 100,
      applyImmediately: true
    });
  }
}
```

### Backup Management

```typescript
// backup.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { RdsBackupService } from '../database/postgres/rds-backup.service';

@Injectable()
export class BackupService {
  private readonly logger = new Logger(BackupService.name);
  
  constructor(private readonly rdsBackupService: RdsBackupService) {}

  async listSnapshots() {
    return this.rdsBackupService.listSnapshots();
  }

  async createManualSnapshot(name: string) {
    this.logger.log(`Creating manual snapshot: ${name}`);
    return this.rdsBackupService.createSnapshot(name);
  }

  async createTimestampedSnapshot(prefix: string = 'manual') {
    const timestamp = new Date().toISOString().replace(/[^0-9]/g, '');
    const snapshotId = `${prefix}-${timestamp}`;
    
    this.logger.log(`Creating timestamped snapshot: ${snapshotId}`);
    return this.rdsBackupService.createSnapshot(snapshotId);
  }
}
```

### Database Parameter Management

```typescript
// database-config.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { RdsParameterService } from '../database/postgres/rds-parameter.service';

@Injectable()
export class DatabaseConfigService {
  private readonly logger = new Logger(DatabaseConfigService.name);
  
  constructor(private readonly rdsParameterService: RdsParameterService) {}

  async getParameters() {
    return this.rdsParameterService.getParameterGroupSettings();
  }

  async optimizeForWeb() {
    this.logger.log('Optimizing database for web workload');
    
    return this.rdsParameterService.updateParameterGroupSettings([
      { name: 'max_connections', value: '200' },
      { name: 'shared_buffers', value: '512MB' },
      { name: 'work_mem', value: '4MB' },
      { name: 'maintenance_work_mem', value: '64MB' },
      { name: 'effective_cache_size', value: '1536MB' },
      { name: 'random_page_cost', value: '1.1' },
    ]);
  }

  async optimizeForOLTP() {
    this.logger.log('Optimizing database for OLTP workload');
    
    return this.rdsParameterService.updateParameterGroupSettings([
      { name: 'max_connections', value: '300' },
      { name: 'shared_buffers', value: '1GB' },
      { name: 'work_mem', value: '8MB' },
      { name: 'maintenance_work_mem', value: '128MB' },
      { name: 'effective_cache_size', value: '3GB' },
      { name: 'random_page_cost', value: '1.1' },
    ]);
  }
}
```

## Creating API Controllers

### Database Health Controller

```typescript
// health.controller.ts
import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { PostgresService } from '../database/postgres/postgres.service';

@ApiTags('Health')
@Controller('health')
export class HealthController {
  constructor(private readonly postgresService: PostgresService) {}

  @Get('database')
  @ApiOperation({ summary: 'Check database health' })
  @ApiResponse({ status: 200, description: 'Database health status' })
  async checkDatabaseHealth() {
    const isHealthy = await this.postgresService.checkHealth();
    
    return {
      status: isHealthy ? 'ok' : 'error',
      message: isHealthy ? 'Database connection is healthy' : 'Database connection failed',
      timestamp: new Date().toISOString(),
    };
  }

  @Get('database/stats')
  @ApiOperation({ summary: 'Get database statistics' })
  @ApiResponse({ status: 200, description: 'Database statistics' })
  async getDatabaseStats() {
    const stats = await this.postgresService.getDatabaseStats();
    const poolStats = await this.postgresService.getConnectionPoolStats();
    
    return {
      size: stats.databaseSize,
      tables: stats.tables.length,
      topTables: stats.tables.slice(0, 5),
      connections: poolStats,
      timestamp: new Date().toISOString(),
    };
  }
}
```

### Database Admin Controller

```typescript
// database-admin.controller.ts
import { Controller, Get, Post, Put, Delete, Param, Body, Query } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiParam, ApiBody, ApiQuery } from '@nestjs/swagger';
import { RdsInstanceService } from '../database/postgres/rds-instance.service';
import { RdsBackupService } from '../database/postgres/rds-backup.service';

@ApiTags('Database Administration')
@Controller('admin/database')
export class DatabaseAdminController {
  constructor(
    private readonly rdsInstanceService: RdsInstanceService,
    private readonly rdsBackupService: RdsBackupService,
  ) {}

  @Get('instances')
  @ApiOperation({ summary: 'List all PostgreSQL RDS instances' })
  @ApiResponse({ status: 200, description: 'List of RDS instances' })
  async listInstances() {
    return this.rdsInstanceService.listInstances();
  }

  @Post('instances')
  @ApiOperation({ summary: 'Create a new PostgreSQL RDS instance' })
  @ApiBody({
    description: 'Instance creation parameters',
    schema: {
      type: 'object',
      required: ['dbInstanceIdentifier'],
      properties: {
        dbInstanceIdentifier: { type: 'string' },
        dbInstanceClass: { type: 'string' },
        allocatedStorage: { type: 'number' },
        multiAZ: { type: 'boolean' },
      }
    }
  })
  @ApiResponse({ status: 201, description: 'RDS instance created' })
  async createInstance(@Body() createParams: any) {
    return this.rdsInstanceService.createInstance(createParams);
  }

  @Post('instances/:id/stop')
  @ApiOperation({ summary: 'Stop an RDS instance' })
  @ApiParam({ name: 'id', description: 'RDS instance identifier' })
  @ApiResponse({ status: 200, description: 'RDS instance stopped' })
  async stopInstance(@Param('id') id: string) {
    return this.rdsInstanceService.stopInstance(id);
  }

  @Post('instances/:id/start')
  @ApiOperation({ summary: 'Start an RDS instance' })
  @ApiParam({ name: 'id', description: 'RDS instance identifier' })
  @ApiResponse({ status: 200, description: 'RDS instance started' })
  async startInstance(@Param('id') id: string) {
    return this.rdsInstanceService.startInstance(id);
  }

  @Get('snapshots')
  @ApiOperation({ summary: 'List all database snapshots' })
  @ApiResponse({ status: 200, description: 'List of database snapshots' })
  async listSnapshots() {
    return this.rdsBackupService.listSnapshots();
  }

  @Post('snapshots')
  @ApiOperation({ summary: 'Create a database snapshot' })
  @ApiBody({
    description: 'Snapshot creation parameters',
    schema: {
      type: 'object',
      required: ['snapshotId'],
      properties: {
        snapshotId: { type: 'string' }
      }
    }
  })
  @ApiResponse({ status: 201, description: 'Database snapshot created' })
  async createSnapshot(@Body() body: { snapshotId: string }) {
    return this.rdsBackupService.createSnapshot(body.snapshotId);
  }
}
```

## Scheduled Tasks

You can use the built-in scheduled tasks or create your own:

```typescript
// database-scheduler.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PostgresMaintenanceService } from '../database/postgres/postgres-maintenance.service';
import { RdsInstanceService } from '../database/postgres/rds-instance.service';

@Injectable()
export class DatabaseSchedulerService {
  private readonly logger = new Logger(DatabaseSchedulerService.name);
  
  constructor(
    private readonly maintenanceService: PostgresMaintenanceService,
    private readonly rdsInstanceService: RdsInstanceService,
  ) {}

  // Run custom maintenance tasks in addition to the built-in ones
  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async runNightlyMaintenance() {
    this.logger.log('Running nightly database maintenance');
    
    try {
      // First run the built-in vacuum
      await this.maintenanceService.runDailyVacuum();
      
      // Then run custom maintenance tasks
      await this.runCustomMaintenance();
      
      this.logger.log('Nightly maintenance completed successfully');
    } catch (error) {
      this.logger.error(`Nightly maintenance failed: ${error.message}`, error.stack);
    }
  }
  
  // Stop development instances during weekends
  @Cron('0 20 * * 5') // At 8:00 PM on Friday
  async stopDevInstancesForWeekend() {
    this.logger.log('Stopping development instances for weekend');
    
    try {
      const instances = await this.rdsInstanceService.listInstances();
      
      // Find development instances that are running
      const devInstances = instances.filter(instance => 
        instance.DBInstanceIdentifier.includes('-dev-') && 
        instance.DBInstanceStatus === 'available'
      );
      
      for (const instance of devInstances) {
        this.logger.log(`Stopping instance for weekend: ${instance.DBInstanceIdentifier}`);
        await this.rdsInstanceService.stopInstance(instance.DBInstanceIdentifier);
      }
    } catch (error) {
      this.logger.error(`Failed to stop dev instances: ${error.message}`, error.stack);
    }
  }
  
  // Start development instances on Monday morning
  @Cron('0 7 * * 1') // At 7:00 AM on Monday
  async startDevInstancesForWeek() {
    this.logger.log('Starting development instances for week');
    
    try {
      const instances = await this.rdsInstanceService.listInstances();
      
      // Find development instances that are stopped
      const stoppedDevInstances = instances.filter(instance => 
        instance.DBInstanceIdentifier.includes('-dev-') && 
        instance.DBInstanceStatus === 'stopped'
      );
      
      for (const instance of stoppedDevInstances) {
        this.logger.log(`Starting instance for week: ${instance.DBInstanceIdentifier}`);
        await this.rdsInstanceService.startInstance(instance.DBInstanceIdentifier);
      }
    } catch (error) {
      this.logger.error(`Failed to start dev instances: ${error.message}`, error.stack);
    }
  }
  
  private async runCustomMaintenance() {
    // Run your custom maintenance tasks here
    // For example, clean up temporary tables, update statistics, etc.
    await this.postgresService.executeQuery('DELETE FROM temp_logs WHERE created_at < NOW() - INTERVAL \'30 days\'');
    await this.postgresService.executeQuery('ANALYZE');
  }
}
```

## Error Handling

Implement proper error handling when using the PostgreSQL module:

```typescript
import { Injectable, Logger, HttpException, HttpStatus } from '@nestjs/common';
import { PostgresService } from '../database/postgres/postgres.service';

@Injectable()
export class DataService {
  private readonly logger = new Logger(DataService.name);
  
  constructor(private readonly postgresService: PostgresService) {}
  
  async getData(id: number) {
    try {
      const result = await this.postgresService.executeQuery('SELECT * FROM data WHERE id = $1', [id]);
      
      if (result.length === 0) {
        throw new HttpException('Data not found', HttpStatus.NOT_FOUND);
      }
      
      return result[0];
    } catch (error) {
      this.logger.error(`Failed to get data: ${error.message}`, error.stack);
      
      if (error instanceof HttpException) {
        throw error;
      }
      
      throw new HttpException('Failed to get data', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}
```
