# AWS RDS PostgreSQL Module

This module provides a comprehensive interface for interacting with AWS RDS PostgreSQL databases in your NestJS application.

## Features

- Connection management with DATABASE_URL support
- Health checks and monitoring
- Database statistics and metrics
- RDS instance lifecycle management (create, delete, stop, start, reboot)
- RDS snapshot management
- RDS parameter group management
- Scheduled maintenance tasks

## Configuration

The module can be configured using environment variables:

### Primary Connection Method

```
DATABASE_URL=postgresql://username:password@hostname:port/database
```

### Fallback Connection Method

If `DATABASE_URL` is not provided, the module will use these individual parameters:

```
RDS_HOST=your-rds-endpoint.rds.amazonaws.com
RDS_PORT=5432
RDS_USER=postgres
RDS_PASSWORD=your_secure_password
RDS_DB=your_database_name
```

### AWS Configuration

```
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
RDS_INSTANCE_ID=your-rds-instance-id
RDS_PARAMETER_GROUP=your-parameter-group-name
```

### Connection Pool Settings

```
DB_POOL_MAX=20
DB_POOL_MIN=5
DB_POOL_IDLE=10000
```

### SSL Configuration

```
RDS_CA_CERT=your_ca_certificate_content
```

## Usage

### Basic Query Execution

```typescript
import { Injectable } from '@nestjs/common';
import { PostgresService } from './database/postgres/postgres.service';

@Injectable()
export class YourService {
  constructor(private readonly postgresService: PostgresService) {}

  async getData() {
    return this.postgresService.executeQuery('SELECT * FROM your_table');
  }
}
```

### Health Checks

```typescript
import { Injectable } from '@nestjs/common';
import { PostgresService } from './database/postgres/postgres.service';

@Injectable()
export class HealthService {
  constructor(private readonly postgresService: PostgresService) {}

  async checkDatabaseHealth() {
    const isHealthy = await this.postgresService.checkHealth();
    return {
      status: isHealthy ? 'ok' : 'error',
      message: isHealthy ? 'Database connection is healthy' : 'Database connection failed',
    };
  }
}
```

### RDS Instance Management

```typescript
import { Injectable } from '@nestjs/common';
import { RdsInstanceService } from './database/postgres/rds-instance.service';

@Injectable()
export class DatabaseService {
  constructor(private readonly rdsInstanceService: RdsInstanceService) {}

  async createDatabase() {
    return this.rdsInstanceService.createInstance({
      dbInstanceIdentifier: 'my-postgres-db',
      dbInstanceClass: 'db.t3.micro',
      allocatedStorage: 20,
      multiAZ: false,
      tags: [
        { Key: 'Environment', Value: 'Development' },
        { Key: 'Project', Value: 'MyProject' }
      ]
    });
  }

  async stopDatabase(instanceId: string) {
    return this.rdsInstanceService.stopInstance(instanceId);
  }

  async startDatabase(instanceId: string) {
    return this.rdsInstanceService.startInstance(instanceId);
  }

  async deleteDatabase(instanceId: string) {
    return this.rdsInstanceService.deleteInstance({
      dbInstanceIdentifier: instanceId,
      skipFinalSnapshot: false,
      finalDBSnapshotIdentifier: `${instanceId}-final-${Date.now()}`
    });
  }
}
```

### RDS Snapshot Management

```typescript
import { Injectable } from '@nestjs/common';
import { RdsBackupService } from './database/postgres/rds-backup.service';

@Injectable()
export class BackupService {
  constructor(private readonly rdsBackupService: RdsBackupService) {}

  async createBackup(name: string) {
    return this.rdsBackupService.createSnapshot(name);
  }

  async listBackups() {
    return this.rdsBackupService.listSnapshots();
  }
}
```

## API Endpoints

The module exposes the following API endpoints:

### Database Operations
- `GET /api/rds/health` - Check database health
- `GET /api/rds/stats` - Get database statistics
- `GET /api/rds/info` - Get RDS instance information
- `GET /api/rds/slow-queries` - Get slow queries
- `GET /api/rds/connection-pool` - Get connection pool statistics

### Instance Management
- `GET /api/rds/instances` - List all PostgreSQL RDS instances
- `GET /api/rds/instances/:id` - Get details of a specific RDS instance
- `POST /api/rds/instances` - Create a new PostgreSQL RDS instance
- `DELETE /api/rds/instances/:id` - Delete an RDS instance
- `POST /api/rds/instances/:id/stop` - Stop an RDS instance
- `POST /api/rds/instances/:id/start` - Start an RDS instance
- `POST /api/rds/instances/:id/reboot` - Reboot an RDS instance
- `PUT /api/rds/instances/:id` - Modify an RDS instance

### Snapshot Management
- `GET /api/rds/snapshots` - List database snapshots
- `POST /api/rds/snapshots` - Create a database snapshot

### Parameter Management
- `GET /api/rds/parameters` - Get RDS parameter group settings
- `POST /api/rds/parameters` - Update RDS parameter group settings

## Scheduled Tasks

The module includes the following scheduled tasks:

- Daily VACUUM ANALYZE at midnight
- Weekly database snapshot creation
- Daily slow query monitoring at 1 AM

## Security

All API endpoints are protected by authentication and authorization guards. Only users with appropriate roles can access sensitive operations.
