import { ApiProperty } from '@nestjs/swagger';

export type InstanceTypeEnum =
  | 't2.micro'
  | 't2.small'
  | 't3.micro'
  | 't3.small'
  | 't3.medium'
  | 't3.large';
// Add more as needed
export class LaunchInstanceDto {
  @ApiProperty({ example: 'ami-0abcdef1234567890' })
  imageId: string;

  @ApiProperty({
    example: 't2.micro',
    enum: ['t2.micro', 't2.small', 't3.micro'],
  })
  instanceType: InstanceTypeEnum;
}
