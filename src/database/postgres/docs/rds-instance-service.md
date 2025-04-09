# RdsInstanceService Documentation

The `RdsInstanceService` provides functionality for managing the complete lifecycle of RDS PostgreSQL instances in your NestJS application.

## Overview

This service handles:
- Creating new RDS PostgreSQL instances
- Deleting instances
- Stopping and starting instances
- Rebooting instances
- Modifying instance configurations
- Retrieving instance information
- Listing all PostgreSQL instances

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

### createInstance

Creates a new RDS PostgreSQL instance with the specified parameters.

```typescript
async createInstance(params: {
  dbInstanceIdentifier: string;
  dbInstanceClass?: string;
  allocatedStorage?: number;
  masterUsername?: string;
  masterUserPassword?: string;
  vpcSecurityGroupIds?: string[];
  dbSubnetGroupName?: string;
  availabilityZone?: string;
  multiAZ?: boolean;
  tags?: { Key: string; Value: string }[];
}): Promise<DBInstance | null> {
  try {
    // Set default values if not provided
    const dbInstanceClass = params.dbInstanceClass || 'db.t3.micro';
    const allocatedStorage = params.allocatedStorage || 20;
    const masterUsername = params.masterUsername || 'postgres';
    const masterUserPassword = params.masterUserPassword || this.generateSecurePassword();
    
    // Prepare command input
    const input: CreateDBInstanceCommandInput = {
      DBInstanceIdentifier: params.dbInstanceIdentifier,
      Engine: 'postgres',
      DBInstanceClass: dbInstanceClass,
      AllocatedStorage: allocatedStorage,
      MasterUsername: masterUsername,
      MasterUserPassword: masterUserPassword,
      BackupRetentionPeriod: 7, // 7 days backup retention
      MultiAZ: params.multiAZ || false,
      AutoMinorVersionUpgrade: true,
      PubliclyAccessible: false,
      StorageType: 'gp2',
      EnablePerformanceInsights: true,
      PerformanceInsightsRetentionPeriod: 7, // 7 days retention for performance insights
      DeletionProtection: true, // Enable deletion protection by default
      Tags: params.tags || [
        {
          Key: 'CreatedBy',
          Value: 'NestJSApplication',
        },
        {
          Key: 'Environment',
          Value: this.configService.get<string>('NODE_ENV') || 'development',
        },
      ],
    };
    
    // Add optional parameters if provided
    if (params.vpcSecurityGroupIds && params.vpcSecurityGroupIds.length > 0) {
      input.VpcSecurityGroupIds = params.vpcSecurityGroupIds;
    }
    
    if (params.dbSubnetGroupName) {
      input.DBSubnetGroupName = params.dbSubnetGroupName;
    }
    
    if (params.availabilityZone) {
      input.AvailabilityZone = params.availabilityZone;
    }
    
    // Create the DB instance
    const command = new CreateDBInstanceCommand(input);
    const response = await this.rdsClient.send(command);
    
    this.logger.log(`Created RDS instance: ${params.dbInstanceIdentifier}`);
    
    // Return the created DB instance
    return response.DBInstance || null;
  } catch (error: any) {
    this.logger.error(`Failed to create RDS instance: ${error.message}`, error.stack);
    throw new Error(`Failed to create RDS instance: ${error.message}`);
  }
}
```

**Usage Example:**
```typescript
// Create a new PostgreSQL RDS instance
const instance = await rdsInstanceService.createInstance({
  dbInstanceIdentifier: 'my-postgres-db',
  dbInstanceClass: 'db.t3.micro',
  allocatedStorage: 20,
  multiAZ: false,
  tags: [
    { Key: 'Environment', Value: 'Development' },
    { Key: 'Project', Value: 'MyProject' }
  ]
});

console.log(`Instance created: ${instance.DBInstanceIdentifier}`);
console.log(`Status: ${instance.DBInstanceStatus}`);
console.log(`Endpoint: ${instance.Endpoint?.Address}`);
```

### deleteInstance

Deletes an RDS PostgreSQL instance with options for final snapshots.

```typescript
async deleteInstance(params: {
  dbInstanceIdentifier: string;
  skipFinalSnapshot?: boolean;
  finalDBSnapshotIdentifier?: string;
}): Promise<DBInstance | null> {
  try {
    // Prepare command input
    const input: DeleteDBInstanceCommandInput = {
      DBInstanceIdentifier: params.dbInstanceIdentifier,
      SkipFinalSnapshot: params.skipFinalSnapshot || false,
    };
    
    // If not skipping final snapshot, set the snapshot identifier
    if (!params.skipFinalSnapshot && !params.finalDBSnapshotIdentifier) {
      // Generate a snapshot name if not provided
      const timestamp = new Date().toISOString().replace(/[^0-9]/g, '');
      input.FinalDBSnapshotIdentifier = `${params.dbInstanceIdentifier}-final-${timestamp}`;
    } else if (params.finalDBSnapshotIdentifier) {
      input.FinalDBSnapshotIdentifier = params.finalDBSnapshotIdentifier;
    }
    
    // Delete the DB instance
    const command = new DeleteDBInstanceCommand(input);
    const response = await this.rdsClient.send(command);
    
    this.logger.log(`Deleted RDS instance: ${params.dbInstanceIdentifier}`);
    
    // Return the deleted DB instance
    return response.DBInstance || null;
  } catch (error: any) {
    this.logger.error(`Failed to delete RDS instance: ${error.message}`, error.stack);
    throw new Error(`Failed to delete RDS instance: ${error.message}`);
  }
}
```

**Usage Example:**
```typescript
// Delete an RDS instance with a final snapshot
const result = await rdsInstanceService.deleteInstance({
  dbInstanceIdentifier: 'my-postgres-db',
  skipFinalSnapshot: false,
  finalDBSnapshotIdentifier: 'my-postgres-db-final-backup'
});

console.log(`Instance deletion initiated: ${result.DBInstanceIdentifier}`);
console.log(`Status: ${result.DBInstanceStatus}`);

// Or delete without a final snapshot
const quickDeleteResult = await rdsInstanceService.deleteInstance({
  dbInstanceIdentifier: 'my-test-db',
  skipFinalSnapshot: true
});
```

### stopInstance

Stops an RDS PostgreSQL instance to save costs during inactive periods.

```typescript
async stopInstance(dbInstanceIdentifier: string): Promise<DBInstance | null> {
  try {
    const command = new StopDBInstanceCommand({
      DBInstanceIdentifier: dbInstanceIdentifier,
    });
    
    const response = await this.rdsClient.send(command);
    
    this.logger.log(`Stopped RDS instance: ${dbInstanceIdentifier}`);
    
    return response.DBInstance || null;
  } catch (error: any) {
    this.logger.error(`Failed to stop RDS instance: ${error.message}`, error.stack);
    throw new Error(`Failed to stop RDS instance: ${error.message}`);
  }
}
```

**Usage Example:**
```typescript
// Stop an RDS instance during non-business hours
const result = await rdsInstanceService.stopInstance('my-postgres-db');
console.log(`Instance stopping: ${result.DBInstanceIdentifier}`);
console.log(`Status: ${result.DBInstanceStatus}`);
```

### startInstance

Starts a stopped RDS PostgreSQL instance.

```typescript
async startInstance(dbInstanceIdentifier: string): Promise<DBInstance | null> {
  try {
    const command = new StartDBInstanceCommand({
      DBInstanceIdentifier: dbInstanceIdentifier,
    });
    
    const response = await this.rdsClient.send(command);
    
    this.logger.log(`Started RDS instance: ${dbInstanceIdentifier}`);
    
    return response.DBInstance || null;
  } catch (error: any) {
    this.logger.error(`Failed to start RDS instance: ${error.message}`, error.stack);
    throw new Error(`Failed to start RDS instance: ${error.message}`);
  }
}
```

**Usage Example:**
```typescript
// Start an RDS instance when needed
const result = await rdsInstanceService.startInstance('my-postgres-db');
console.log(`Instance starting: ${result.DBInstanceIdentifier}`);
console.log(`Status: ${result.DBInstanceStatus}`);
```

### rebootInstance

Reboots an RDS PostgreSQL instance, optionally with failover for Multi-AZ instances.

```typescript
async rebootInstance(dbInstanceIdentifier: string, forceFailover: boolean = false): Promise<DBInstance | null> {
  try {
    const command = new RebootDBInstanceCommand({
      DBInstanceIdentifier: dbInstanceIdentifier,
      ForceFailover: forceFailover,
    });
    
    const response = await this.rdsClient.send(command);
    
    this.logger.log(`Rebooted RDS instance: ${dbInstanceIdentifier}`);
    
    return response.DBInstance || null;
  } catch (error: any) {
    this.logger.error(`Failed to reboot RDS instance: ${error.message}`, error.stack);
    throw new Error(`Failed to reboot RDS instance: ${error.message}`);
  }
}
```

**Usage Example:**
```typescript
// Reboot an RDS instance
const result = await rdsInstanceService.rebootInstance('my-postgres-db');
console.log(`Instance rebooting: ${result.DBInstanceIdentifier}`);

// Reboot with failover (for Multi-AZ instances)
const failoverResult = await rdsInstanceService.rebootInstance('my-production-db', true);
```

### modifyInstance

Modifies an RDS PostgreSQL instance configuration.

```typescript
async modifyInstance(params: {
  dbInstanceIdentifier: string;
  dbInstanceClass?: string;
  allocatedStorage?: number;
  masterUserPassword?: string;
  backupRetentionPeriod?: number;
  preferredBackupWindow?: string;
  preferredMaintenanceWindow?: string;
  multiAZ?: boolean;
  engineVersion?: string;
  allowMajorVersionUpgrade?: boolean;
  autoMinorVersionUpgrade?: boolean;
  applyImmediately?: boolean;
}): Promise<DBInstance | null> {
  try {
    // Prepare command input
    const input: ModifyDBInstanceCommandInput = {
      DBInstanceIdentifier: params.dbInstanceIdentifier,
      ApplyImmediately: params.applyImmediately || false,
    };
    
    // Add optional parameters if provided
    if (params.dbInstanceClass) {
      input.DBInstanceClass = params.dbInstanceClass;
    }
    
    if (params.allocatedStorage) {
      input.AllocatedStorage = params.allocatedStorage;
    }
    
    if (params.masterUserPassword) {
      input.MasterUserPassword = params.masterUserPassword;
    }
    
    if (params.backupRetentionPeriod !== undefined) {
      input.BackupRetentionPeriod = params.backupRetentionPeriod;
    }
    
    if (params.preferredBackupWindow) {
      input.PreferredBackupWindow = params.preferredBackupWindow;
    }
    
    if (params.preferredMaintenanceWindow) {
      input.PreferredMaintenanceWindow = params.preferredMaintenanceWindow;
    }
    
    if (params.multiAZ !== undefined) {
      input.MultiAZ = params.multiAZ;
    }
    
    if (params.engineVersion) {
      input.EngineVersion = params.engineVersion;
    }
    
    if (params.allowMajorVersionUpgrade !== undefined) {
      input.AllowMajorVersionUpgrade = params.allowMajorVersionUpgrade;
    }
    
    if (params.autoMinorVersionUpgrade !== undefined) {
      input.AutoMinorVersionUpgrade = params.autoMinorVersionUpgrade;
    }
    
    // Modify the DB instance
    const command = new ModifyDBInstanceCommand(input);
    const response = await this.rdsClient.send(command);
    
    this.logger.log(`Modified RDS instance: ${params.dbInstanceIdentifier}`);
    
    // Return the modified DB instance
    return response.DBInstance || null;
  } catch (error: any) {
    this.logger.error(`Failed to modify RDS instance: ${error.message}`, error.stack);
    throw new Error(`Failed to modify RDS instance: ${error.message}`);
  }
}
```

**Usage Example:**
```typescript
// Scale up an RDS instance
const result = await rdsInstanceService.modifyInstance({
  dbInstanceIdentifier: 'my-postgres-db',
  dbInstanceClass: 'db.t3.medium',
  allocatedStorage: 50,
  applyImmediately: true
});

console.log(`Instance modification initiated: ${result.DBInstanceIdentifier}`);
console.log(`New instance class: ${result.DBInstanceClass}`);
console.log(`New allocated storage: ${result.AllocatedStorage} GB`);

// Update backup settings
const backupResult = await rdsInstanceService.modifyInstance({
  dbInstanceIdentifier: 'my-postgres-db',
  backupRetentionPeriod: 14,
  preferredBackupWindow: '03:00-04:00',
  applyImmediately: false
});
```

### getInstance

Gets detailed information about a specific RDS PostgreSQL instance.

```typescript
async getInstance(dbInstanceIdentifier: string): Promise<DBInstance> {
  try {
    const command = new DescribeDBInstancesCommand({
      DBInstanceIdentifier: dbInstanceIdentifier,
    });
    
    const response = await this.rdsClient.send(command);
    
    if (!response.DBInstances || response.DBInstances.length === 0) {
      throw new Error(`RDS instance not found: ${dbInstanceIdentifier}`);
    }
    
    return response.DBInstances[0];
  } catch (error: any) {
    this.logger.error(`Failed to get RDS instance: ${error.message}`, error.stack);
    throw new Error(`Failed to get RDS instance: ${error.message}`);
  }
}
```

**Usage Example:**
```typescript
// Get information about a specific RDS instance
const instance = await rdsInstanceService.getInstance('my-postgres-db');

console.log(`Instance: ${instance.DBInstanceIdentifier}`);
console.log(`Status: ${instance.DBInstanceStatus}`);
console.log(`Class: ${instance.DBInstanceClass}`);
console.log(`Storage: ${instance.AllocatedStorage} GB`);
console.log(`Endpoint: ${instance.Endpoint?.Address}:${instance.Endpoint?.Port}`);
console.log(`Multi-AZ: ${instance.MultiAZ}`);
console.log(`Engine: ${instance.Engine} ${instance.EngineVersion}`);
```

### listInstances

Lists all RDS PostgreSQL instances.

```typescript
async listInstances(): Promise<DBInstance[]> {
  try {
    const command = new DescribeDBInstancesCommand({});
    const response = await this.rdsClient.send(command);
    
    // Filter to only return PostgreSQL instances
    const postgresInstances = response.DBInstances?.filter(
      instance => instance.Engine === 'postgres'
    ) || [];
    
    return postgresInstances;
  } catch (error: any) {
    this.logger.error(`Failed to list RDS instances: ${error.message}`, error.stack);
    throw new Error(`Failed to list RDS instances: ${error.message}`);
  }
}
```

**Usage Example:**
```typescript
// List all PostgreSQL RDS instances
const instances = await rdsInstanceService.listInstances();

console.log(`Found ${instances.length} PostgreSQL instances:`);
instances.forEach(instance => {
  console.log(`- ${instance.DBInstanceIdentifier} (${instance.DBInstanceStatus})`);
  console.log(`  Class: ${instance.DBInstanceClass}, Storage: ${instance.AllocatedStorage} GB`);
  console.log(`  Endpoint: ${instance.Endpoint?.Address}:${instance.Endpoint?.Port}`);
});
```

## Complete Usage Example

```typescript
import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { RdsInstanceService } from './database/postgres/rds-instance.service';

@Injectable()
export class DatabaseSchedulerService {
  private readonly logger = new Logger(DatabaseSchedulerService.name);
  
  constructor(private readonly rdsInstanceService: RdsInstanceService) {}
  
  // Stop development databases during non-business hours to save costs
  @Cron('0 20 * * 1-5') // At 8:00 PM, Monday through Friday
  async stopDevDatabases() {
    try {
      const instances = await this.rdsInstanceService.listInstances();
      
      // Find development instances that are running
      const devInstances = instances.filter(instance => 
        instance.DBInstanceIdentifier.includes('-dev-') && 
        instance.DBInstanceStatus === 'available'
      );
      
      this.logger.log(`Found ${devInstances.length} development instances to stop`);
      
      // Stop each development instance
      for (const instance of devInstances) {
        this.logger.log(`Stopping instance: ${instance.DBInstanceIdentifier}`);
        await this.rdsInstanceService.stopInstance(instance.DBInstanceIdentifier);
      }
    } catch (error) {
      this.logger.error(`Failed to stop development databases: ${error.message}`, error.stack);
    }
  }
  
  // Start development databases during business hours
  @Cron('0 8 * * 1-5') // At 8:00 AM, Monday through Friday
  async startDevDatabases() {
    try {
      const instances = await this.rdsInstanceService.listInstances();
      
      // Find development instances that are stopped
      const stoppedDevInstances = instances.filter(instance => 
        instance.DBInstanceIdentifier.includes('-dev-') && 
        instance.DBInstanceStatus === 'stopped'
      );
      
      this.logger.log(`Found ${stoppedDevInstances.length} development instances to start`);
      
      // Start each stopped development instance
      for (const instance of stoppedDevInstances) {
        this.logger.log(`Starting instance: ${instance.DBInstanceIdentifier}`);
        await this.rdsInstanceService.startInstance(instance.DBInstanceIdentifier);
      }
    } catch (error) {
      this.logger.error(`Failed to start development databases: ${error.message}`, error.stack);
    }
  }
  
  // Scale up production databases during peak hours
  @Cron('0 9 * * 1-5') // At 9:00 AM, Monday through Friday
  async scaleUpForPeakHours() {
    try {
      const prodInstance = await this.rdsInstanceService.getInstance('my-production-db');
      
      if (prodInstance.DBInstanceClass === 'db.t3.medium') {
        this.logger.log('Scaling up production database for peak hours');
        
        await this.rdsInstanceService.modifyInstance({
          dbInstanceIdentifier: 'my-production-db',
          dbInstanceClass: 'db.t3.large',
          applyImmediately: true
        });
      }
    } catch (error) {
      this.logger.error(`Failed to scale up production database: ${error.message}`, error.stack);
    }
  }
  
  // Scale down production databases during off-peak hours
  @Cron('0 19 * * 1-5') // At 7:00 PM, Monday through Friday
  async scaleDownForOffPeakHours() {
    try {
      const prodInstance = await this.rdsInstanceService.getInstance('my-production-db');
      
      if (prodInstance.DBInstanceClass === 'db.t3.large') {
        this.logger.log('Scaling down production database for off-peak hours');
        
        await this.rdsInstanceService.modifyInstance({
          dbInstanceIdentifier: 'my-production-db',
          dbInstanceClass: 'db.t3.medium',
          applyImmediately: true
        });
      }
    } catch (error) {
      this.logger.error(`Failed to scale down production database: ${error.message}`, error.stack);
    }
  }
}
```
