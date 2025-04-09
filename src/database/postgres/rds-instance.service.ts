import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  RDSClient,
  CreateDBInstanceCommand,
  DeleteDBInstanceCommand,
  StopDBInstanceCommand,
  StartDBInstanceCommand,
  DescribeDBInstancesCommand,
  ModifyDBInstanceCommand,
  RebootDBInstanceCommand,
  DBInstance,
  CreateDBInstanceCommandInput,
  DeleteDBInstanceCommandInput,
  ModifyDBInstanceCommandInput,
} from '@aws-sdk/client-rds';

@Injectable()
export class RdsInstanceService {
  private readonly logger = new Logger(RdsInstanceService.name);
  private rdsClient: RDSClient;

  constructor(private readonly configService: ConfigService) {
    // Get region and credentials from environment variables
    const region = this.configService.get<string>('AWS_REGION') || 'us-east-1';
    const accessKeyId = this.configService.get<string>('AWS_ACCESS_KEY_ID');
    const secretAccessKey = this.configService.get<string>(
      'AWS_SECRET_ACCESS_KEY',
    );

    // Only provide credentials if both values are available
    const clientConfig: any = { region };

    if (accessKeyId && secretAccessKey) {
      clientConfig.credentials = {
        accessKeyId,
        secretAccessKey,
      };
    }

    this.rdsClient = new RDSClient(clientConfig);
  }

  /**
   * Create a new RDS PostgreSQL instance
   */
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
      const masterUserPassword =
        params.masterUserPassword || this.generateSecurePassword();

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
      this.logger.error(
        `Failed to create RDS instance: ${error.message}`,
        error.stack,
      );
      throw new Error(`Failed to create RDS instance: ${error.message}`);
    }
  }

  /**
   * Delete an RDS PostgreSQL instance
   */
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
      this.logger.error(
        `Failed to delete RDS instance: ${error.message}`,
        error.stack,
      );
      throw new Error(`Failed to delete RDS instance: ${error.message}`);
    }
  }

  /**
   * Stop an RDS PostgreSQL instance
   */
  async stopInstance(dbInstanceIdentifier: string): Promise<DBInstance | null> {
    try {
      const command = new StopDBInstanceCommand({
        DBInstanceIdentifier: dbInstanceIdentifier,
      });

      const response = await this.rdsClient.send(command);

      this.logger.log(`Stopped RDS instance: ${dbInstanceIdentifier}`);

      return response.DBInstance || null;
    } catch (error: any) {
      this.logger.error(
        `Failed to stop RDS instance: ${error.message}`,
        error.stack,
      );
      throw new Error(`Failed to stop RDS instance: ${error.message}`);
    }
  }

  /**
   * Start an RDS PostgreSQL instance
   */
  async startInstance(
    dbInstanceIdentifier: string,
  ): Promise<DBInstance | null> {
    try {
      const command = new StartDBInstanceCommand({
        DBInstanceIdentifier: dbInstanceIdentifier,
      });

      const response = await this.rdsClient.send(command);

      this.logger.log(`Started RDS instance: ${dbInstanceIdentifier}`);

      return response.DBInstance || null;
    } catch (error: any) {
      this.logger.error(
        `Failed to start RDS instance: ${error.message}`,
        error.stack,
      );
      throw new Error(`Failed to start RDS instance: ${error.message}`);
    }
  }

  /**
   * Reboot an RDS PostgreSQL instance
   */
  async rebootInstance(
    dbInstanceIdentifier: string,
    forceFailover: boolean = false,
  ): Promise<DBInstance | null> {
    try {
      const command = new RebootDBInstanceCommand({
        DBInstanceIdentifier: dbInstanceIdentifier,
        ForceFailover: forceFailover,
      });

      const response = await this.rdsClient.send(command);

      this.logger.log(`Rebooted RDS instance: ${dbInstanceIdentifier}`);

      return response.DBInstance || null;
    } catch (error: any) {
      this.logger.error(
        `Failed to reboot RDS instance: ${error.message}`,
        error.stack,
      );
      throw new Error(`Failed to reboot RDS instance: ${error.message}`);
    }
  }

  /**
   * Modify an RDS PostgreSQL instance
   */
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
      this.logger.error(
        `Failed to modify RDS instance: ${error.message}`,
        error.stack,
      );
      throw new Error(`Failed to modify RDS instance: ${error.message}`);
    }
  }

  /**
   * Get information about an RDS PostgreSQL instance
   */
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
      this.logger.error(
        `Failed to get RDS instance: ${error.message}`,
        error.stack,
      );
      throw new Error(`Failed to get RDS instance: ${error.message}`);
    }
  }

  /**
   * List all RDS PostgreSQL instances
   */
  async listInstances(): Promise<DBInstance[]> {
    try {
      const command = new DescribeDBInstancesCommand({});
      const response = await this.rdsClient.send(command);

      // Filter to only return PostgreSQL instances
      const postgresInstances =
        response.DBInstances?.filter(
          (instance) => instance.Engine === 'postgres',
        ) || [];

      return postgresInstances;
    } catch (error: any) {
      this.logger.error(
        `Failed to list RDS instances: ${error.message}`,
        error.stack,
      );
      throw new Error(`Failed to list RDS instances: ${error.message}`);
    }
  }

  /**
   * Generate a secure random password for RDS
   * @private
   */
  private generateSecurePassword(): string {
    const length = 16;
    const charset =
      'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&()*+,-./:;<=>?@[]^_`{|}~';
    let password = '';

    // Ensure at least one character from each required group
    password += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random() * 26)]; // Uppercase
    password += 'abcdefghijklmnopqrstuvwxyz'[Math.floor(Math.random() * 26)]; // Lowercase
    password += '0123456789'[Math.floor(Math.random() * 10)]; // Digit
    password += '!#$%&()*+,-./:;<=>?@[]^_`{|}~'[Math.floor(Math.random() * 31)]; // Special char

    // Fill the rest with random characters
    for (let i = 4; i < length; i++) {
      password += charset[Math.floor(Math.random() * charset.length)];
    }

    // Shuffle the password
    return password
      .split('')
      .sort(() => 0.5 - Math.random())
      .join('');
  }
}
