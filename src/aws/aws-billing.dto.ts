import { ApiProperty } from '@nestjs/swagger';
import { MetricValue } from '@aws-sdk/client-cost-explorer';

export class CostAndUsageResponse {
  @ApiProperty({
    description: 'The total cost for the requested time period.',
    type: Object, // You could also define a more specific type if you know the structure
  })
  TotalCost: Record<string, MetricValue> | Record<string, any>; // Support AWS SDK type

  @ApiProperty({
    description: 'The granularity of the cost report (e.g., monthly).',
    example: 'MONTHLY',
  })
  Granularity: string;

  @ApiProperty({
    description: 'The start date of the report.',
    example: '2025-01-01',
  })
  StartDate: string;

  @ApiProperty({
    description: 'The end date of the report.',
    example: '2025-01-31',
  })
  EndDate: string;
}
