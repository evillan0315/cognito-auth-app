import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  RDSClient,
  CreateDBSnapshotCommand,
  DescribeDBSnapshotsCommand,
} from '@aws-sdk/client-rds';

@Injectable()
export class RdsBackupService {
  private readonly logger = new Logger(RdsBackupService.name);
  private rdsClient: RDSClient;

  constructor(private readonly configService: ConfigService) {
    // Fix: Ensure credentials are not undefined
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
   * Create a database snapshot
   */
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
      this.logger.error(
        `Failed to create snapshot: ${error.message}`,
        error.stack,
      );
      throw new Error(`Failed to create database snapshot: ${error.message}`);
    }
  }

  /**
   * List database snapshots
   */
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
      this.logger.error(
        `Failed to list snapshots: ${error.message}`,
        error.stack,
      );
      throw new Error(`Failed to list database snapshots: ${error.message}`);
    }
  }
}
