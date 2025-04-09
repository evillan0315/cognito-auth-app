import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  RDSClient,
  DescribeDBParametersCommand,
  ModifyDBParameterGroupCommand,
} from '@aws-sdk/client-rds';

@Injectable()
export class RdsParameterService {
  private readonly logger = new Logger(RdsParameterService.name);
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
   * Get RDS parameter group settings
   */
  async getParameterGroupSettings(): Promise<any> {
    try {
      const parameterGroupName = this.configService.get<string>(
        'RDS_PARAMETER_GROUP',
      );

      if (!parameterGroupName) {
        throw new Error('RDS_PARAMETER_GROUP is not configured');
      }

      const command = new DescribeDBParametersCommand({
        DBParameterGroupName: parameterGroupName,
      });

      const response = await this.rdsClient.send(command);
      return response.Parameters;
    } catch (error: any) {
      this.logger.error(
        `Failed to get parameter group: ${error.message}`,
        error.stack,
      );
      throw new Error(
        `Failed to get RDS parameter group settings: ${error.message}`,
      );
    }
  }

  /**
   * Update RDS parameter group settings
   */
  async updateParameterGroupSettings(
    parameters: Array<{ name: string; value: string }>,
  ): Promise<any> {
    try {
      const parameterGroupName = this.configService.get<string>(
        'RDS_PARAMETER_GROUP',
      );

      if (!parameterGroupName) {
        throw new Error('RDS_PARAMETER_GROUP is not configured');
      }

      const command = new ModifyDBParameterGroupCommand({
        DBParameterGroupName: parameterGroupName,
        Parameters: parameters.map((param) => ({
          ParameterName: param.name,
          ParameterValue: param.value,
          ApplyMethod: 'pending-reboot', // or 'immediate' for dynamic parameters
        })),
      });

      const response = await this.rdsClient.send(command);
      this.logger.log(`Updated parameter group: ${parameterGroupName}`);

      return response;
    } catch (error: any) {
      this.logger.error(
        `Failed to update parameter group: ${error.message}`,
        error.stack,
      );
      throw new Error(
        `Failed to update RDS parameter group settings: ${error.message}`,
      );
    }
  }
}
