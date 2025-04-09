# RdsParameterService Documentation

The `RdsParameterService` provides functionality for managing RDS parameter groups in your NestJS application.

## Overview

This service handles:
- Retrieving parameter group settings
- Updating parameter group settings

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

### getParameterGroupSettings

Gets the current settings for the RDS parameter group.

```typescript
async getParameterGroupSettings(): Promise<any> {
  try {
    const parameterGroupName = this.configService.get<string>('RDS_PARAMETER_GROUP');
    
    if (!parameterGroupName) {
      throw new Error('RDS_PARAMETER_GROUP is not configured');
    }
    
    const command = new DescribeDBParametersCommand({
      DBParameterGroupName: parameterGroupName,
    });
    
    const response = await this.rdsClient.send(command);
    return response.Parameters;
  } catch (error: any) {
    this.logger.error(`Failed to get parameter group: ${error.message}`, error.stack);
    throw new Error(`Failed to get RDS parameter group settings: ${error.message}`);
  }
}
```

**Usage Example:**
```typescript
// Get all parameters in the parameter group
const parameters = await rdsParameterService.getParameterGroupSettings();

console.log(`Found ${parameters.length} parameters:`);
parameters.forEach(param => {
  console.log(`- ${param.ParameterName}: ${param.ParameterValue}`);
  console.log(`  Description: ${param.Description}`);
  console.log(`  Allowed Values: ${param.AllowedValues}`);
  console.log(`  Apply Type: ${param.ApplyType}`);
});

// Find specific parameters
const maxConnections = parameters.find(p => p.ParameterName === 'max_connections');
console.log(`Max connections: ${maxConnections?.ParameterValue}`);

const sharedBuffers = parameters.find(p => p.ParameterName === 'shared_buffers');
console.log(`Shared buffers: ${sharedBuffers?.ParameterValue}`);
```

### updateParameterGroupSettings

Updates settings in the RDS parameter group.

```typescript
async updateParameterGroupSettings(parameters: Array<{ name: string, value: string }>): Promise<any> {
  try {
    const parameterGroupName = this.configService.get<string>('RDS_PARAMETER_GROUP');
    
    if (!parameterGroupName) {
      throw new Error('RDS_PARAMETER_GROUP is not configured');
    }
    
    const command = new ModifyDBParameterGroupCommand({
      DBParameterGroupName: parameterGroupName,
      Parameters: parameters.map(param => ({
        ParameterName: param.name,
        ParameterValue: param.value,
        ApplyMethod: 'pending-reboot', // or 'immediate' for dynamic parameters
      })),
    });
    
    const response = await this.rdsClient.send(command);
    this.logger.log(`Updated parameter group: ${parameterGroupName}`);
    
    return response;
  } catch (error: any) {
    this.logger.error(`Failed to update parameter group: ${error.message}`, error.stack);
    throw new Error(`Failed to update RDS parameter group settings: ${error.message}`);
  }
}
```

**Usage Example:**
```typescript
// Update multiple parameters at once
const result = await rdsParameterService.updateParameterGroupSettings([
  { name: 'max_connections', value: '200' },
  { name: 'shared_buffers', value: '1GB' },
  { name: 'work_mem', value: '16MB' },
  { name: 'maintenance_work_mem', value: '256MB' },
]);

console.log(`Parameter group update status: ${result.DBParameterGroupName}`);

// After updating parameters that require a reboot, you would need to reboot the instance
// using the RdsInstanceService.rebootInstance method
```

## Complete Usage Example

```typescript
import { Injectable, Logger } from '@nestjs/common';
import { RdsParameterService } from './database/postgres/rds-parameter.service';
import { RdsInstanceService } from './database/postgres/rds-instance.service';

@Injectable()
export class DatabaseOptimizationService {
  private readonly logger = new Logger(DatabaseOptimizationService.name);
  
  constructor(
    private readonly rdsParameterService: RdsParameterService,
    private readonly rdsInstanceService: RdsInstanceService,
  ) {}
  
  async optimizeDatabaseForWorkload(instanceId: string, workloadType: 'web' | 'oltp' | 'dw' | 'mixed') {
    try {
      // Get instance details to determine size
      const instance = await this.rdsInstanceService.getInstance(instanceId);
      
      // Calculate optimal parameters based on instance class and workload type
      const parameters = this.calculateOptimalParameters(instance.DBInstanceClass, workloadType);
      
      this.logger.log(`Optimizing database ${instanceId} for ${workloadType} workload`);
      
      // Update the parameter group with the calculated parameters
      await this.rdsParameterService.updateParameterGroupSettings(parameters);
      
      this.logger.log(`Parameter group updated, rebooting instance to apply changes`);
      
      // Reboot the instance to apply the changes
      await this.rdsInstanceService.rebootInstance(instanceId);
      
      return {
        status: 'success',
        message: `Database ${instanceId} optimized for ${workloadType} workload`,
        parameters,
      };
    } catch (error) {
      this.logger.error(`Failed to optimize database: ${error.message}`, error.stack);
      throw new Error(`Failed to optimize database: ${error.message}`);
    }
  }
  
  private calculateOptimalParameters(instanceClass: string, workloadType: string): Array<{ name: string, value: string }> {
    // Extract instance size information
    const sizeMatch = instanceClass.match(/\.([a-z]+)(\d+)?/);
    const size = sizeMatch ? sizeMatch[1] : 't3';
    const multiplier = sizeMatch && sizeMatch[2] ? parseInt(sizeMatch[2], 10) : 1;
    
    // Base memory allocation in MB based on instance size
    let baseMemory = 0;
    switch (size) {
      case 't3': baseMemory = 2048; break;
      case 'm5': baseMemory = 8192; break;
      case 'r5': baseMemory = 16384; break;
      default: baseMemory = 4096;
    }
    
    const totalMemory = baseMemory * multiplier;
    
    // Calculate parameters based on workload type and available memory
    switch (workloadType) {
      case 'web':
        return [
          { name: 'max_connections', value: '200' },
          { name: 'shared_buffers', value: `${Math.floor(totalMemory * 0.25)}MB` },
          { name: 'work_mem', value: `${Math.floor(totalMemory * 0.05)}MB` },
          { name: 'maintenance_work_mem', value: `${Math.floor(totalMemory * 0.1)}MB` },
          { name: 'effective_cache_size', value: `${Math.floor(totalMemory * 0.75)}MB` },
          { name: 'random_page_cost', value: '1.1' },
        ];
      
      case 'oltp':
        return [
          { name: 'max_connections', value: '300' },
          { name: 'shared_buffers', value: `${Math.floor(totalMemory * 0.3)}MB` },
          { name: 'work_mem', value: `${Math.floor(totalMemory * 0.03)}MB` },
          { name: 'maintenance_work_mem', value: `${Math.floor(totalMemory * 0.15)}MB` },
          { name: 'effective_cache_size', value: `${Math.floor(totalMemory * 0.8)}MB` },
          { name: 'random_page_cost', value: '1.1' },
        ];
      
      case 'dw':
        return [
          { name: 'max_connections', value: '100' },
          { name: 'shared_buffers', value: `${Math.floor(totalMemory * 0.4)}MB` },
          { name: 'work_mem', value: `${Math.floor(totalMemory * 0.1)}MB` },
          { name: 'maintenance_work_mem', value: `${Math.floor(totalMemory * 0.2)}MB` },
          { name: 'effective_cache_size', value: `${Math.floor(totalMemory * 0.6)}MB` },
          { name: 'random_page_cost', value: '2.0' },
        ];
      
      case 'mixed':
      default:
        return [
          { name: 'max_connections', value: '150' },
          { name: 'shared_buffers', value: `${Math.floor(totalMemory * 0.25)}MB` },
          { name: 'work_mem', value: `${Math.floor(totalMemory * 0.05)}MB` },
          { name: 'maintenance_work_mem', value: `${Math.floor(totalMemory * 0.15)}MB` },
          { name: 'effective_cache_size', value: `${Math.floor(totalMemory * 0.7)}MB` },
          { name: 'random_page_cost', value: '1.5' },
        ];
    }
  }
}
```
