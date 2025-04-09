import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, Matches } from 'class-validator';

export class CreateSnapshotDto {
  @ApiProperty({
    description: 'The identifier for the DB snapshot',
    example: 'my-snapshot-2025-04-09',
  })
  @IsNotEmpty()
  @IsString()
  @Matches(/^[a-zA-Z0-9-]+$/, {
    message: 'Snapshot ID can only contain alphanumeric characters and hyphens',
  })
  snapshotId: string;
}
