# PostgresMaintenanceService Documentation

The `PostgresMaintenanceService` provides scheduled maintenance tasks for PostgreSQL databases in your NestJS application.

## Overview

This service handles:
- Running daily VACUUM ANALYZE operations
- Creating weekly database snapshots
- Monitoring slow queries

## Constructor

```typescript
constructor(
  private readonly postgresService: PostgresService,
  private readonly rdsBackupService: RdsBackupService,
  private readonly configService: ConfigService,
) {
  this.logger.log('PostgreSQL maintenance service initialized');
}
```

## Methods

### runDailyVacuum

Runs VACUUM ANALYZE on all tables to reclaim storage and update statistics. This method is scheduled to run daily at midnight.

```typescript
@Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
async runDailyVacuum() {
  try {
    this.logger.log('Running daily VACUUM ANALYZE');
    
    // Get all tables in the current database
    const tablesQuery = `
      SELECT tablename
      FROM pg_tables
      WHERE schemaname = 'public'
    `;
    
    const tables = await this.postgresService.executeQuery(tablesQuery);
    
    // Run VACUUM ANALYZE on each table
    for (const table of tables) {
      const tableName = table.tablename;
      this.logger.log(`Running VACUUM ANALYZE on table: ${tableName}`);
      
      await this.postgresService.executeQuery(`VACUUM ANALYZE ${tableName}`);
    }
    
    this.logger.log('Daily VACUUM ANALYZE completed');
  } catch (error: any) {
    this.logger.error(`Failed to run daily VACUUM: ${error.message}`, error.stack);
  }
}
```

**Usage Example:**
```typescript
// This method is automatically scheduled to run daily at midnight
// You can also trigger it manually if needed:
await postgresMaintenanceService.runDailyVacuum();
```

### createWeeklySnapshot

Creates a weekly snapshot of the database for backup purposes. This method is scheduled to run every Sunday at 1 AM.

```typescript
@Cron('0 1 * * 0') // Every Sunday at 1 AM
async createWeeklySnapshot() {
  try {
    const date = new Date();
    const formattedDate = date.toISOString().split('T')[0];
    const snapshotId = `weekly-backup-${formattedDate}`;
    
    this.logger.log(`Creating weekly snapshot: ${snapshotId}`);
    
    await this.rdsBackupService.createSnapshot(snapshotId);
    
    this.logger.log('Weekly snapshot created');
  } catch (error: any) {
    this.logger.error(`Failed to create weekly snapshot: ${error.message}`, error.stack);
  }
}
```

**Usage Example:**
```typescript
// This method is automatically scheduled to run every Sunday at 1 AM
// You can also trigger it manually if needed:
await postgresMaintenanceService.createWeeklySnapshot();
```

### monitorSlowQueries

Monitors slow queries and logs them for analysis. This method is scheduled to run daily at 1 AM.

```typescript
@Cron('0 1 * * *') // Every day at 1 AM
async monitorSlowQueries() {
  try {
    this.logger.log('Monitoring slow queries');
    
    const slowQueries = await this.postgresService.getSlowQueries();
    
    if (slowQueries.length > 0) {
      this.logger.log(`Found ${slowQueries.length} slow queries`);
      
      // Log the top 5 slowest queries
      const top5 = slowQueries.slice(0, 5);
      top5.forEach((query, index) => {
        this.logger.warn(`Slow query #${index + 1}:`);
        this.logger.warn(`Query: ${query.query}`);
        if (query.avg_time) {
          this.logger.warn(`Average time: ${query.avg_time}ms`);
        }
        if (query.calls) {
          this.logger.warn(`Calls: ${query.calls}`);
        }
        if (query.duration) {
          this.logger.warn(`Duration: ${query.duration}`);
        }
      });
      
      // Here you could implement additional logic to store slow queries
      // in a database table for historical analysis
    } else {
      this.logger.log('No slow queries found');
    }
  } catch (error: any) {
    this.logger.error(`Failed to monitor slow queries: ${error.message}`, error.stack);
  }
}
```

**Usage Example:**
```typescript
// This method is automatically scheduled to run daily at 1 AM
// You can also trigger it manually if needed:
await postgresMaintenanceService.monitorSlowQueries();
```

## Complete Usage Example

```typescript
import { Injectable, Logger } from '@nestjs/common';
import { PostgresMaintenanceService } from './database/postgres/postgres-maintenance.service';

@Injectable()
export class DatabaseMaintenanceController {
  private readonly logger = new Logger(DatabaseMaintenanceController.name);
  
  constructor(private readonly maintenanceService: PostgresMaintenanceService) {}
  
  async runFullMaintenance() {
    this.logger.log('Starting full database maintenance');
    
    try {
      // Run all maintenance tasks in sequence
      await this.maintenanceService.runDailyVacuum();
      await this.maintenanceService.monitorSlowQueries();
      await this.maintenanceService.createWeeklySnapshot();
      
      this.logger.log('Full database maintenance completed successfully');
      
      return {
        status: 'success',
        message: 'Full database maintenance completed successfully',
      };
    } catch (error) {
      this.logger.error(`Maintenance failed: ${error.message}`, error.stack);
      
      return {
        status: 'error',
        message: `Maintenance failed: ${error.message}`,
      };
    }
  }
  
  async runVacuumOnly() {
    this.logger.log('Running VACUUM ANALYZE only');
    
    try {
      await this.maintenanceService.runDailyVacuum();
      
      return {
        status: 'success',
        message: 'VACUUM ANALYZE completed successfully',
      };
    } catch (error) {
      this.logger.error(`VACUUM ANALYZE failed: ${error.message}`, error.stack);
      
      return {
        status: 'error',
        message: `VACUUM ANALYZE failed: ${error.message}`,
      };
    }
  }
  
  async createManualSnapshot(snapshotId: string) {
    this.logger.log(`Creating manual snapshot: ${snapshotId}`);
    
    try {
      // Use the underlying RdsBackupService through the maintenance service
      await this.maintenanceService['rdsBackupService'].createSnapshot(snapshotId);
      
      return {
        status: 'success',
        message: `Manual snapshot ${snapshotId} created successfully`,
      };
    } catch (error) {
      this.logger.error(`Manual snapshot failed: ${error.message}`, error.stack);
      
      return {
        status: 'error',
        message: `Manual snapshot failed: ${error.message}`,
      };
    }
  }
}
```
