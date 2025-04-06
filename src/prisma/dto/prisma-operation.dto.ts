import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class PrismaOperationDto {
  @ApiProperty({ example: 'task', description: 'The Prisma model name' })
  model: string;

  @ApiProperty({
    example: 'findMany',
    description: 'The Prisma operation to perform',
  })
  operation: string;

  @ApiPropertyOptional({
    description: 'The data payload for create/update operations',
  })
  data?: any;
}
