# RdsBackupService Documentation

The `RdsBackupService` provides functionality for managing RDS snapshots in your NestJS application.

## Overview

This service handles:
- Creating database snapshots
- Listing existing snapshots

## Constructor

```typescript
constructor(private readonly configService: ConfigService) {
  // Get region and credentials from environment variables
  const region = this.configService.get<string>('AWS_REGION') || 'us-east-1';
  const accessKeyId = this.configService.get<string>('AWS_ACCESS_KEY_ID');
  const secretAccessKey = this.configService.get<string>('AWS_SECRET_ACCESS_KEY');
  
  // Only provide credentials if both values are available
  const clientConfig: any = { region };
  
  if (accessKeyId && secretAccessKey) {
    clientConfig.credentials = {
      accessKeyId,
      secretAccessKey
    };
  }
  
  this.rdsClient = new RDSClient(clientConfig);
}
```

## Methods

### createSnapshot

Creates a database snapshot with the specified ID.

```typescript
async createSnapshot(snapshotId: string): Promise<any> {
  try {
    const dbInstanceId = this.configService.get<string>('RDS_INSTANCE_ID');
    
    if (!dbInstanceId) {
      throw new Error('RDS_INSTANCE_ID is not configured');
    }
    
    const command = new CreateDBSnapshotCommand({
      DBSnapshotIdentifier: snapshotId,
      DBInstanceIdentifier: dbInstanceId,
      Tags: [
        {
          Key: 'CreatedBy',
          Value: 'NestJSApplication',
        },
        {
          Key: 'Environment',
          Value: this.configService.get<string>('NODE_ENV') || 'development',
        },
      ],
    });
    
    const response = await this.rdsClient.send(command);
    this.logger.log(`Created snapshot: ${snapshotId}`);
    
    return response;
  } catch (error: any) {
    this.logger.error(`Failed to create snapshot: ${error.message}`, error.stack);
    throw new Error(`Failed to create database snapshot: ${error.message}`);
  }
}
```

**Usage Example:**
```typescript
// Create a snapshot with a timestamp-based name
const timestamp = new Date().toISOString().replace(/[^0-9]/g, '');
const snapshotId = `my-db-snapshot-${timestamp}`;
const result = await rdsBackupService.createSnapshot(snapshotId);
console.log(`Snapshot created: ${result.DBSnapshot.DBSnapshotIdentifier}`);
console.log(`Status: ${result.DBSnapshot.Status}`);
```

### listSnapshots

Lists all database snapshots for the configured RDS instance.

```typescript
async listSnapshots(): Promise<any> {
  try {
    const dbInstanceId = this.configService.get<string>('RDS_INSTANCE_ID');
    
    if (!dbInstanceId) {
      throw new Error('RDS_INSTANCE_ID is not configured');
    }
    
    const command = new DescribeDBSnapshotsCommand({
      DBInstanceIdentifier: dbInstanceId,
    });
    
    const response = await this.rdsClient.send(command);
    return response.DBSnapshots;
  } catch (error: any) {
    this.logger.error(`Failed to list snapshots: ${error.message}`, error.stack);
    throw new Error(`Failed to list database snapshots: ${error.message}`);
  }
}
```

**Usage Example:**
```typescript
// List all snapshots for the configured RDS instance
const snapshots = await rdsBackupService.listSnapshots();
console.log(`Found ${snapshots.length} snapshots:`);
snapshots.forEach(snapshot => {
  console.log(`- ${snapshot.DBSnapshotIdentifier} (${snapshot.Status})`);
  console.log(`  Created: ${snapshot.SnapshotCreateTime}`);
  console.log(`  Size: ${snapshot.AllocatedStorage} GB`);
});
```

## Complete Usage Example

```typescript
import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { RdsBackupService } from './database/postgres/rds-backup.service';

@Injectable()
export class BackupSchedulerService {
  private readonly logger = new Logger(BackupSchedulerService.name);
  
  constructor(private readonly rdsBackupService: RdsBackupService) {}
  
  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async createDailyBackup() {
    try {
      const date = new Date();
      const formattedDate = date.toISOString().split('T')[0];
      const snapshotId = `daily-backup-${formattedDate}`;
      
      this.logger.log(`Creating daily backup: ${snapshotId}`);
      const result = await this.rdsBackupService.createSnapshot(snapshotId);
      
      this.logger.log(`Daily backup created: ${result.DBSnapshot.DBSnapshotIdentifier}`);
    } catch (error) {
      this.logger.error(`Failed to create daily backup: ${error.message}`, error.stack);
    }
  }
  
  @Cron(CronExpression.EVERY_WEEK)
  async cleanupOldBackups() {
    try {
      const snapshots = await this.rdsBackupService.listSnapshots();
      
      // Find snapshots older than 30 days
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
      
      const oldSnapshots = snapshots.filter(snapshot => {
        const snapshotDate = new Date(snapshot.SnapshotCreateTime);
        return snapshotDate < thirtyDaysAgo && snapshot.DBSnapshotIdentifier.startsWith('daily-backup-');
      });
      
      this.logger.log(`Found ${oldSnapshots.length} snapshots older than 30 days`);
      
      // Here you would implement logic to delete old snapshots
      // using the AWS SDK DeleteDBSnapshotCommand
    } catch (error) {
      this.logger.error(`Failed to clean up old backups: ${error.message}`, error.stack);
    }
  }
}
```
