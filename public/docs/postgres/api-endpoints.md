# API Endpoints Documentation

This document provides detailed information about the API endpoints exposed by the PostgreSQL module.

## Database Operations

### Check Database Health

```
GET /api/rds/health
```

Checks if the database connection is healthy.

**Response:**
```json
{
  "status": "ok",
  "message": "Database connection is healthy"
}
```

**Error Response:**
```json
{
  "status": "error",
  "message": "Database connection failed"
}
```

**Usage Example:**
```typescript
// Using Axios
const response = await axios.get('/api/rds/health');
console.log(response.data);
```

### Get Database Statistics

```
GET /api/rds/stats
```

Gets statistics about the database, including table sizes, row counts, and index usage.

**Response:**
```json
{
  "databaseSize": "256 MB",
  "tables": [
    {
      "table_name": "users",
      "row_count": 10000,
      "total_size": "32 MB"
    },
    {
      "table_name": "orders",
      "row_count": 50000,
      "total_size": "128 MB"
    }
  ],
  "indexes": [
    {
      "index_name": "users_pkey",
      "table_name": "users",
      "index_scans": 15000,
      "index_size": "8 MB"
    }
  ],
  "connections": [
    {
      "state": "active",
      "count": "5"
    },
    {
      "state": "idle",
      "count": "10"
    }
  ]
}
```

**Usage Example:**
```typescript
// Using Axios
const response = await axios.get('/api/rds/stats');
console.log(`Database size: ${response.data.databaseSize}`);
console.log(`Number of tables: ${response.data.tables.length}`);
```

### Get RDS Instance Information

```
GET /api/rds/info
```

Gets detailed information about the RDS instance.

**Response:**
```json
{
  "version": "PostgreSQL 13.4 on x86_64-pc-linux-gnu, compiled by gcc (GCC) 7.3.1 20180712 (Red Hat 7.3.1-12), 64-bit",
  "instanceInfo": {
    "db_name": "mydb",
    "pg_version": "13.4",
    "db_size": "512 MB",
    "max_connections": "100",
    "active_connections": "15",
    "shared_buffers": "128MB",
    "work_mem": "4MB",
    "maintenance_work_mem": "64MB",
    "effective_cache_size": "4GB"
  },
  "connectionInfo": {
    "usingDatabaseUrl": true,
    "host": "mydb.cluster-abcdefghijkl.us-east-1.rds.amazonaws.com",
    "database": "mydb"
  }
}
```

**Usage Example:**
```typescript
// Using Axios
const response = await axios.get('/api/rds/info');
console.log(`PostgreSQL version: ${response.data.instanceInfo.pg_version}`);
console.log(`Database size: ${response.data.instanceInfo.db_size}`);
```

### Get Slow Queries

```
GET /api/rds/slow-queries
```

Gets a list of slow queries for analysis.

**Response:**
```json
[
  {
    "query": "SELECT * FROM users JOIN orders ON users.id = orders.user_id WHERE users.created_at > $1",
    "calls": 1500,
    "avg_time": 1250.45,
    "min_time": 800.12,
    "max_time": 3500.67,
    "mean_time": 1250.45,
    "stddev_time": 450.32,
    "rows": 5000
  },
  {
    "query": "UPDATE orders SET status = $1 WHERE created_at < $2",
    "calls": 500,
    "avg_time": 950.78,
    "min_time": 500.34,
    "max_time": 2500.12,
    "mean_time": 950.78,
    "stddev_time": 350.45,
    "rows": 2500
  }
]
```

**Usage Example:**
```typescript
// Using Axios
const response = await axios.get('/api/rds/slow-queries');
console.log(`Found ${response.data.length} slow queries`);
response.data.forEach((query, index) => {
  console.log(`Query #${index + 1}: ${query.query}`);
  console.log(`Average time: ${query.avg_time}ms, Calls: ${query.calls}`);
});
```

### Get Connection Pool Statistics

```
GET /api/rds/connection-pool
```

Gets statistics about the database connection pool.

**Response:**
```json
{
  "total": 15,
  "active": 5,
  "idle": 10
}
```

**Usage Example:**
```typescript
// Using Axios
const response = await axios.get('/api/rds/connection-pool');
console.log(`Total connections: ${response.data.total}`);
console.log(`Active connections: ${response.data.active}`);
console.log(`Idle connections: ${response.data.idle}`);
```

## Instance Management

### List All PostgreSQL RDS Instances

```
GET /api/rds/instances
```

Lists all PostgreSQL RDS instances.

**Response:**
```json
[
  {
    "DBInstanceIdentifier": "my-postgres-db",
    "DBInstanceClass": "db.t3.micro",
    "Engine": "postgres",
    "DBInstanceStatus": "available",
    "MasterUsername": "postgres",
    "Endpoint": {
      "Address": "my-postgres-db.abcdefghijkl.us-east-1.rds.amazonaws.com",
      "Port": 5432
    },
    "AllocatedStorage": 20,
    "InstanceCreateTime": "2023-01-15T12:00:00.000Z",
    "PreferredBackupWindow": "03:00-04:00",
    "BackupRetentionPeriod": 7,
    "DBSecurityGroups": [],
    "VpcSecurityGroups": [
      {
        "VpcSecurityGroupId": "sg-0123456789abcdef",
        "Status": "active"
      }
    ],
    "DBParameterGroups": [
      {
        "DBParameterGroupName": "default.postgres13",
        "ParameterApplyStatus": "in-sync"
      }
    ],
    "AvailabilityZone": "us-east-1a",
    "DBSubnetGroup": {
      "DBSubnetGroupName": "default",
      "DBSubnetGroupDescription": "default",
      "VpcId": "vpc-0123456789abcdef",
      "SubnetGroupStatus": "Complete",
      "Subnets": [
        {
          "SubnetIdentifier": "subnet-0123456789abcdef",
          "SubnetAvailabilityZone": {
            "Name": "us-east-1a"
          },
          "SubnetStatus": "Active"
        }
      ]
    },
    "MultiAZ": false,
    "EngineVersion": "13.4",
    "AutoMinorVersionUpgrade": true,
    "PubliclyAccessible": false,
    "StorageType": "gp2",
    "StorageEncrypted": true,
    "DbiResourceId": "db-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "CACertificateIdentifier": "rds-ca-2019",
    "DomainMemberships": [],
    "CopyTagsToSnapshot": true,
    "MonitoringInterval": 0,
    "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:my-postgres-db",
    "IAMDatabaseAuthenticationEnabled": false,
    "PerformanceInsightsEnabled": true,
    "PerformanceInsightsKMSKeyId": "arn:aws:kms:us-east-1:123456789012:key/abcdefgh-1234-5678-9012-abcdefghijkl",
    "PerformanceInsightsRetentionPeriod": 7,
    "DeletionProtection": true,
    "MaxAllocatedStorage": 1000,
    "TagList": [
      {
        "Key": "Environment",
        "Value": "Development"
      }
    ]
  }
]
```

**Usage Example:**
```typescript
// Using Axios
const response = await axios.get('/api/rds/instances');
console.log(`Found ${response.data.length} PostgreSQL instances`);
response.data.forEach(instance => {
  console.log(`- ${instance.DBInstanceIdentifier} (${instance.DBInstanceStatus})`);
  console.log(`  Endpoint: ${instance.Endpoint.Address}:${instance.Endpoint.Port}`);
});
```

### Get Details of a Specific RDS Instance

```
GET /api/rds/instances/:id
```

Gets detailed information about a specific RDS instance.

**Parameters:**
- `id` (path parameter): The RDS instance identifier

**Response:**
Same as a single instance object from the list endpoint.

**Usage Example:**
```typescript
// Using Axios
const instanceId = 'my-postgres-db';
const response = await axios.get(`/api/rds/instances/${instanceId}`);
console.log(`Instance: ${response.data.DBInstanceIdentifier}`);
console.log(`Status: ${response.data.DBInstanceStatus}`);
console.log(`Endpoint: ${response.data.Endpoint.Address}:${response.data.Endpoint.Port}`);
```

### Create a New PostgreSQL RDS Instance

```
POST /api/rds/instances
```

Creates a new PostgreSQL RDS instance.

**Request Body:**
```json
{
  "dbInstanceIdentifier": "my-new-postgres-db",
  "dbInstanceClass": "db.t3.micro",
  "allocatedStorage": 20,
  "masterUsername": "postgres",
  "masterUserPassword": "StrongPassword123!",
  "vpcSecurityGroupIds": ["sg-0123456789abcdef"],
  "dbSubnetGroupName": "my-db-subnet-group",
  "availabilityZone": "us-east-1a",
  "multiAZ": false,
  "tags": [
    {
      "Key": "Environment",
      "Value": "Development"
    },
    {
      "Key": "Project",
      "Value": "MyProject"
    }
  ]
}
```

**Response:**
Same as a single instance object from the list endpoint, with status typically "creating".

**Usage Example:**
```typescript
// Using Axios
const createParams = {
  dbInstanceIdentifier: 'my-new-postgres-db',
  dbInstanceClass: 'db.t3.micro',
  allocatedStorage: 20,
  multiAZ: false,
  tags: [
    { Key: 'Environment', Value: 'Development' },
    { Key: 'Project', Value: 'MyProject' }
  ]
};

const response = await axios.post('/api/rds/instances', createParams);
console.log(`Instance creation initiated: ${response.data.DBInstanceIdentifier}`);
console.log(`Status: ${response.data.DBInstanceStatus}`);
```

### Delete an RDS Instance

```
DELETE /api/rds/instances/:id
```

Deletes an RDS instance.

**Parameters:**
- `id` (path parameter): The RDS instance identifier
- `skipFinalSnapshot` (query parameter, optional): Whether to skip taking a final snapshot (default: false)
- `finalDBSnapshotIdentifier` (query parameter, optional): Name for the final snapshot

**Response:**
Same as a single instance object from the list endpoint, with status typically "deleting".

**Usage Example:**
```typescript
// Using Axios
const instanceId = 'my-postgres-db';

// Delete with a final snapshot
const response = await axios.delete(`/api/rds/instances/${instanceId}?finalDBSnapshotIdentifier=my-postgres-db-final`);

// Or delete without a final snapshot
const quickDeleteResponse = await axios.delete(`/api/rds/instances/${instanceId}?skipFinalSnapshot=true`);

console.log(`Instance deletion initiated: ${response.data.DBInstanceIdentifier}`);
console.log(`Status: ${response.data.DBInstanceStatus}`);
```

### Stop an RDS Instance

```
POST /api/rds/instances/:id/stop
```

Stops an RDS instance.

**Parameters:**
- `id` (path parameter): The RDS instance identifier

**Response:**
Same as a single instance object from the list endpoint, with status typically "stopping".

**Usage Example:**
```typescript
// Using Axios
const instanceId = 'my-postgres-db';
const response = await axios.post(`/api/rds/instances/${instanceId}/stop`);
console.log(`Instance stopping: ${response.data.DBInstanceIdentifier}`);
console.log(`Status: ${response.data.DBInstanceStatus}`);
```

### Start an RDS Instance

```
POST /api/rds/instances/:id/start
```

Starts an RDS instance.

**Parameters:**
- `id` (path parameter): The RDS instance identifier

**Response:**
Same as a single instance object from the list endpoint, with status typically "starting".

**Usage Example:**
```typescript
// Using Axios
const instanceId = 'my-postgres-db';
const response = await axios.post(`/api/rds/instances/${instanceId}/start`);
console.log(`Instance starting: ${response.data.DBInstanceIdentifier}`);
console.log(`Status: ${response.data.DBInstanceStatus}`);
```

### Reboot an RDS Instance

```
POST /api/rds/instances/:id/reboot
```

Reboots an RDS instance.

**Parameters:**
- `id` (path parameter): The RDS instance identifier
- `forceFailover` (query parameter, optional): Whether to force a failover during reboot (default: false)

**Response:**
Same as a single instance object from the list endpoint, with status typically "rebooting".

**Usage Example:**
```typescript
// Using Axios
const instanceId = 'my-postgres-db';

// Simple reboot
const response = await axios.post(`/api/rds/instances/${instanceId}/reboot`);

// Reboot with failover (for Multi-AZ instances)
const failoverResponse = await axios.post(`/api/rds/instances/${instanceId}/reboot?forceFailover=true`);

console.log(`Instance rebooting: ${response.data.DBInstanceIdentifier}`);
console.log(`Status: ${response.data.DBInstanceStatus}`);
```

### Modify an RDS Instance

```
PUT /api/rds/instances/:id
```

Modifies an RDS instance configuration.

**Parameters:**
- `id` (path parameter): The RDS instance identifier

**Request Body:**
```json
{
  "dbInstanceClass": "db.t3.small",
  "allocatedStorage": 30,
  "masterUserPassword": "NewStrongPassword123!",
  "backupRetentionPeriod": 14,
  "preferredBackupWindow": "03:00-04:00",
  "preferredMaintenanceWindow": "sun:05:00-sun:06:00",
  "multiAZ": true,
  "engineVersion": "13.7",
  "allowMajorVersionUpgrade": false,
  "autoMinorVersionUpgrade": true,
  "applyImmediately": false
}
```

**Response:**
Same as a single instance object from the list endpoint, with status typically "modifying".

**Usage Example:**
```typescript
// Using Axios
const instanceId = 'my-postgres-db';
const modifyParams = {
  dbInstanceClass: 'db.t3.small',
  allocatedStorage: 30,
  backupRetentionPeriod: 14,
  applyImmediately: true
};

const response = await axios.put(`/api/rds/instances/${instanceId}`, modifyParams);
console.log(`Instance modification initiated: ${response.data.DBInstanceIdentifier}`);
console.log(`New instance class: ${response.data.DBInstanceClass}`);
```

## Snapshot Management

### List Database Snapshots

```
GET /api/rds/snapshots
```

Lists all database snapshots for the configured RDS instance.

**Response:**
```json
[
  {
    "DBSnapshotIdentifier": "weekly-backup-2023-01-15",
    "DBInstanceIdentifier": "my-postgres-db",
    "SnapshotCreateTime": "2023-01-15T01:00:00.000Z",
    "Engine": "postgres",
    "AllocatedStorage": 20,
    "Status": "available",
    "Port": 5432,
    "AvailabilityZone": "us-east-1a",
    "VpcId": "vpc-0123456789abcdef",
    "InstanceCreateTime": "2023-01-01T12:00:00.000Z",
    "MasterUsername": "postgres",
    "EngineVersion": "13.4",
    "LicenseModel": "postgresql-license",
    "SnapshotType": "manual",
    "PercentProgress": 100,
    "StorageType": "gp2",
    "Encrypted": true,
    "DBSnapshotArn": "arn:aws:rds:us-east-1:123456789012:snapshot:weekly-backup-2023-01-15",
    "TagList": [
      {
        "Key": "CreatedBy",
        "Value": "NestJSApplication"
      }
    ]
  }
]
```

**Usage Example:**
```typescript
// Using Axios
const response = await axios.get('/api/rds/snapshots');
console.log(`Found ${response.data.length} snapshots`);
response.data.forEach(snapshot => {
  console.log(`- ${snapshot.DBSnapshotIdentifier} (${snapshot.Status})`);
  console.log(`  Created: ${snapshot.SnapshotCreateTime}`);
  console.log(`  Size: ${snapshot.AllocatedStorage} GB`);
});
```

### Create a Database Snapshot

```
POST /api/rds/snapshots
```

Creates a database snapshot.

**Request Body:**
```json
{
  "snapshotId": "my-manual-snapshot"
}
```

**Response:**
```json
{
  "DBSnapshot": {
    "DBSnapshotIdentifier": "my-manual-snapshot",
    "DBInstanceIdentifier": "my-postgres-db",
    "SnapshotCreateTime": "2023-01-20T15:30:00.000Z",
    "Engine": "postgres",
    "AllocatedStorage": 20,
    "Status": "creating",
    "Port": 5432,
    "AvailabilityZone": "us-east-1a",
    "VpcId": "vpc-0123456789abcdef",
    "InstanceCreateTime": "2023-01-01T12:00:00.000Z",
    "MasterUsername": "postgres",
    "EngineVersion": "13.4",
    "LicenseModel": "postgresql-license",
    "SnapshotType": "manual",
    "PercentProgress": 0,
    "StorageType": "gp2",
    "Encrypted": true,
    "DBSnapshotArn": "arn:aws:rds:us-east-1:123456789012:snapshot:my-manual-snapshot",
    "TagList": [
      {
        "Key": "CreatedBy",
        "Value": "NestJSApplication"
      }
    ]
  }
}
```

**Usage Example:**
```typescript
// Using Axios
const response = await axios.post('/api/rds/snapshots', {
  snapshotId: 'my-manual-snapshot'
});
console.log(`Snapshot creation initiated: ${response.data.DBSnapshot.DBSnapshotIdentifier}`);
console.log(`Status: ${response.data.DBSnapshot.Status}`);
```

## Parameter Management

### Get RDS Parameter Group Settings

```
GET /api/rds/parameters
```

Gets the current settings for the RDS parameter group.

**Response:**
```json
[
  {
    "ParameterName": "max_connections",
    "ParameterValue": "100",
    "Description": "Sets the maximum number of concurrent connections.",
    "Source": "system",
    "ApplyType": "dynamic",
    "DataType": "integer",
    "AllowedValues": "1-262143",
    "IsModifiable": true,
    "ApplyMethod": "immediate"
  },
  {
    "ParameterName": "shared_buffers",
    "ParameterValue": "128MB",
    "Description": "Sets the number of shared memory buffers used by the server.",
    "Source": "system",
    "ApplyType": "static",
    "DataType": "string",
    "AllowedValues": "8KB-1073741823KB",
    "IsModifiable": true,
    "ApplyMethod": "pending-reboot"
  }
]
```

**Usage Example:**
```typescript
// Using Axios
const response = await axios.get('/api/rds/parameters');
console.log(`Found ${response.data.length} parameters`);
response.data.forEach(param => {
  console.log(`- ${param.ParameterName}: ${param.ParameterValue}`);
  console.log(`  Description: ${param.Description}`);
  console.log(`  Apply Type: ${param.ApplyType}`);
});
```

### Update RDS Parameter Group Settings

```
POST /api/rds/parameters
```

Updates settings in the RDS parameter group.

**Request Body:**
```json
{
  "parameters": [
    {
      "name": "max_connections",
      "value": "200"
    },
    {
      "name": "shared_buffers",
      "value": "1GB"
    },
    {
      "name": "work_mem",
      "value": "16MB"
    }
  ]
}
```

**Response:**
```json
{
  "DBParameterGroupName": "my-parameter-group",
  "DBParameterGroupFamily": "postgres13"
}
```

**Usage Example:**
```typescript
// Using Axios
const response = await axios.post('/api/rds/parameters', {
  parameters: [
    { name: 'max_connections', value: '200' },
    { name: 'shared_buffers', value: '1GB' },
    { name: 'work_mem', value: '16MB' }
  ]
});
console.log(`Parameter group updated: ${response.data.DBParameterGroupName}`);
```
