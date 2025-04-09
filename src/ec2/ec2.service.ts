import { Injectable } from '@nestjs/common';
import {
  EC2Client,
  DescribeInstancesCommand,
  StartInstancesCommand,
  StopInstancesCommand,
  TerminateInstancesCommand,
  RunInstancesCommand,
  _InstanceType, // 🛠️ This is important
} from '@aws-sdk/client-ec2';
import { ConfigService } from '@nestjs/config';
import { LaunchInstanceDto } from './launch-instance.dto';

@Injectable()
export class Ec2Service {
  private ec2: EC2Client;

  constructor(private configService: ConfigService) {
    this.ec2 = new EC2Client({
      region: this.configService.get<string>('AWS_REGION')!,
      credentials: {
        accessKeyId: this.configService.get<string>('AWS_ACCESS_KEY_ID')!,
        secretAccessKey: this.configService.get<string>(
          'AWS_SECRET_ACCESS_KEY',
        )!,
      },
    });
  }

  async listInstances() {
    const command = new DescribeInstancesCommand({});
    const response = await this.ec2.send(command);
    return response.Reservations?.flatMap((r) => r.Instances) || [];
  }

  async startInstance(instanceId: string) {
    const command = new StartInstancesCommand({ InstanceIds: [instanceId] });
    return this.ec2.send(command);
  }

  async stopInstance(instanceId: string) {
    const command = new StopInstancesCommand({ InstanceIds: [instanceId] });
    return this.ec2.send(command);
  }

  async terminateInstance(instanceId: string) {
    const command = new TerminateInstancesCommand({
      InstanceIds: [instanceId],
    });
    return this.ec2.send(command);
  }

  async launchInstance(dto: LaunchInstanceDto) {
    const command = new RunInstancesCommand({
      ImageId: dto.imageId,
      InstanceType: dto.instanceType as _InstanceType, // 👈 Cast here
      MinCount: 1,
      MaxCount: 1,
    });
    return this.ec2.send(command);
  }
}
