# AWS RDS PostgreSQL Module Documentation

This documentation provides a comprehensive guide to the AWS RDS PostgreSQL module in the NestJS application.

## Table of Contents

1. [Overview](#overview)
2. [Module Structure](#module-structure)
3. [Configuration](#configuration)
4. [Services](#services)
   - [PostgresService](#postgresservice)
   - [RdsBackupService](#rdsbackupservice)
   - [RdsParameterService](#rdsparameterservice)
   - [RdsInstanceService](#rdsinstanceservice)
   - [PostgresMaintenanceService](#postgresmaintenanceservice)
5. [Controllers](#controllers)
   - [PostgresController](#postgrescontroller)
   - [RdsInstanceController](#rdsinstancecontroller)
6. [API Endpoints](#api-endpoints)
7. [Usage Examples](#usage-examples)
8. [Best Practices](#best-practices)

## Overview

The AWS RDS PostgreSQL module provides a comprehensive interface for interacting with AWS RDS PostgreSQL databases in your NestJS application. It includes features for:

- Connection management with DATABASE_URL support
- Health checks and monitoring
- Database statistics and metrics
- RDS instance lifecycle management (create, delete, stop, start, reboot)
- RDS snapshot management
- RDS parameter group management
- Scheduled maintenance tasks

## Module Structure

The module is organized as follows:

```
src/database/postgres/
├── postgres.module.ts           # Main module definition
├── postgres.service.ts          # Core PostgreSQL service
├── postgres.controller.ts       # API endpoints for PostgreSQL operations
├── rds-backup.service.ts        # RDS snapshot management
├── rds-parameter.service.ts     # RDS parameter group management
├── rds-instance.service.ts      # RDS instance lifecycle management
├── postgres-maintenance.service.ts # Scheduled maintenance tasks
├── rds-instance.controller.ts   # API endpoints for RDS instance management
└── docs/                        # Documentation
```

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

## Services

### PostgresService

The `PostgresService` provides core functionality for interacting with PostgreSQL databases.

#### Methods

- `getConnection()`: Get the database connection
- `executeQuery(query: string, parameters: any[] = [])`: Execute a raw SQL query
- `checkHealth()`: Check database connection health
- `getRdsInstanceInfo()`: Get RDS instance information
- `getDatabaseStats()`: Get database statistics
- `getSlowQueries()`: Monitor slow queries
- `getConnectionPoolStats()`: Get connection pool statistics

#### Usage Example

```typescript
import { Injectable } from '@nestjs/common';
import { PostgresService } from './database/postgres/postgres.service';

@Injectable()
export class YourService {
  constructor(private readonly postgresService: PostgresService) {}

  async getData() {
    return this.postgresService.executeQuery('SELECT * FROM your_table');
  }
  
  async checkDatabaseHealth() {
    const isHealthy = await this.postgresService.checkHealth();
    return {
      status: isHealthy ? 'ok' : 'error',
      message: isHealthy ? 'Database connection is healthy' : 'Database connection failed',
    };
  }
}
```

### RdsBackupService

The `RdsBackupService` provides functionality for managing RDS snapshots.

#### Methods

- `createSnapshot(snapshotId: string)`: Create a database snapshot
- `listSnapshots()`: List database snapshots

#### Usage Example

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

### RdsParameterService

The `RdsParameterService` provides functionality for managing RDS parameter groups.

#### Methods

- `getParameterGroupSettings()`: Get RDS parameter group settings
- `updateParameterGroupSettings(parameters: Array<{ name: string, value: string }>)`: Update RDS parameter group settings

#### Usage Example

```typescript
import { Injectable } from '@nestjs/common';
import { RdsParameterService } from './database/postgres/rds-parameter.service';

@Injectable()
export class DatabaseConfigService {
  constructor(private readonly rdsParameterService: RdsParameterService) {}

  async getParameters() {
    return this.rdsParameterService.getParameterGroupSettings();
  }

  async updateParameters(parameters: Array<{ name: string, value: string }>) {
    return this.rdsParameterService.updateParameterGroupSettings(parameters);
  }
}
```

### RdsInstanceService

The `RdsInstanceService` provides functionality for managing RDS instance lifecycle.

#### Methods

- `createInstance(params: {...})`: Create a new RDS PostgreSQL instance
- `deleteInstance(params: {...})`: Delete an RDS PostgreSQL instance
- `stopInstance(dbInstanceIdentifier: string)`: Stop an RDS PostgreSQL instance
- `startInstance(dbInstanceIdentifier: string)`: Start an RDS PostgreSQL instance
- `rebootInstance(dbInstanceIdentifier: string, forceFailover: boolean = false)`: Reboot an RDS PostgreSQL instance
- `modifyInstance(params: {...})`: Modify an RDS PostgreSQL instance
- `getInstance(dbInstanceIdentifier: string)`: Get information about an RDS PostgreSQL instance
- `listInstances()`: List all RDS PostgreSQL instances

#### Usage Example

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

### PostgresMaintenanceService

The `PostgresMaintenanceService` provides scheduled maintenance tasks for PostgreSQL databases.

#### Methods

- `runDailyVacuum()`: Run VACUUM ANALYZE on all tables (scheduled daily)
- `createWeeklySnapshot()`: Create a weekly snapshot (scheduled weekly)
- `monitorSlowQueries()`: Monitor slow queries (scheduled daily)

## Controllers

### PostgresController

The `PostgresController` provides API endpoints for PostgreSQL operations.

#### Endpoints

- `GET /api/rds/health`: Check database health
- `GET /api/rds/stats`: Get database statistics
- `GET /api/rds/info`: Get RDS instance information
- `GET /api/rds/slow-queries`: Get slow queries
- `GET /api/rds/connection-pool`: Get connection pool statistics

### RdsInstanceController

The `RdsInstanceController` provides API endpoints for RDS instance management.

#### Endpoints

- `GET /api/rds/instances`: List all PostgreSQL RDS instances
- `GET /api/rds/instances/:id`: Get details of a specific RDS instance
- `POST /api/rds/instances`: Create a new PostgreSQL RDS instance
- `DELETE /api/rds/instances/:id`: Delete an RDS instance
- `POST /api/rds/instances/:id/stop`: Stop an RDS instance
- `POST /api/rds/instances/:id/start`: Start an RDS instance
- `POST /api/rds/instances/:id/reboot`: Reboot an RDS instance
- `PUT /api/rds/instances/:id`: Modify an RDS instance

## API Endpoints

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

## Usage Examples

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

## Best Practices

1. **Connection Management**:
   - Use the DATABASE_URL environment variable for connection configuration
   - Provide fallback values for all connection parameters
   - Use connection pooling for optimal performance

2. **Security**:
   - Store sensitive credentials in environment variables
   - Enable SSL for production environments
   - Use deletion protection for production databases
   - Implement proper access controls for API endpoints

3. **Backup Strategy**:
   - Create regular automated snapshots
   - Test snapshot restoration periodically
   - Implement a retention policy for snapshots

4. **Monitoring**:
   - Regularly check database health
   - Monitor slow queries and optimize as needed
   - Set up alerts for critical database metrics

5. **Cost Optimization**:
   - Stop non-production instances during off-hours
   - Use appropriate instance sizes for your workload
   - Monitor and optimize storage usage
