import {
  IsNotEmpty,
  IsString,
  IsEnum,
  IsNumber,
  IsOptional,
  ValidateIf,
  IsArray,
  ValidateNested,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
// Define DTOs for nested DynamoDB objects (assuming these are in the same file or imported)
export class DynamoDBKeySchemaElementDto {
  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  AttributeName: string;

  @ApiProperty({ enum: ['HASH', 'RANGE'] })
  @IsNotEmpty()
  @IsEnum(['HASH', 'RANGE'])
  KeyType: 'HASH' | 'RANGE';
}

export class DynamoDBAttributeDefinitionDto {
  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  AttributeName: string;

  @ApiProperty({ enum: ['S', 'N', 'B'] })
  @IsNotEmpty()
  @IsEnum(['S', 'N', 'B'])
  AttributeType: 'S' | 'N' | 'B';
}

export class DynamoDBProvisionedThroughputDto {
  @ApiProperty()
  @IsNotEmpty()
  @IsNumber()
  ReadCapacityUnits: number;

  @ApiProperty()
  @IsNotEmpty()
  @IsNumber()
  WriteCapacityUnits: number;
}

export class CreateDatabaseConnectionDto {
  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  name: string;

  @ApiProperty({
    enum: ['mongodb', 'mysql', 'postgresql', 'sqlite', 'dynamodb'],
  })
  @IsNotEmpty()
  @IsEnum(['mongodb', 'mysql', 'postgresql', 'sqlite', 'dynamodb'])
  type: 'mongodb' | 'mysql' | 'postgresql' | 'sqlite' | 'dynamodb';

  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  @ValidateIf((o) => o.type !== 'dynamodb' && !o.connectionString)
  host?: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsNumber()
  @ValidateIf((o) => o.type !== 'dynamodb' && !o.connectionString)
  port?: number;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  @ValidateIf((o) => o.type !== 'dynamodb' && !o.connectionString)
  username?: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  @ValidateIf((o) => o.type !== 'dynamodb' && !o.connectionString)
  password?: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  @ValidateIf((o) => o.type !== 'dynamodb' && !o.connectionString)
  databaseName?: string;

  @ApiProperty({
    required: false,
    description:
      'Complete database connection string. If provided, individual connection details (host, port, etc.) are optional for non-DynamoDB types.',
  })
  @IsOptional()
  @IsString()
  @ValidateIf(
    (o) => o.type !== 'dynamodb' && (!o.host || !o.port || !o.databaseName),
  )
  connectionString?: string;

  // DynamoDB Specific Fields (Optional)
  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @ValidateIf((o) => o.type === 'dynamodb')
  dynamoDBTableName?: string;

  @ApiPropertyOptional({ type: [DynamoDBKeySchemaElementDto] })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => DynamoDBKeySchemaElementDto)
  @ValidateIf((o) => o.type === 'dynamodb')
  dynamoDBKeySchema?: DynamoDBKeySchemaElementDto[];

  @ApiPropertyOptional({ type: [DynamoDBAttributeDefinitionDto] })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => DynamoDBAttributeDefinitionDto)
  @ValidateIf((o) => o.type === 'dynamodb')
  dynamoDBAttributeDefinitions?: DynamoDBAttributeDefinitionDto[];

  @ApiPropertyOptional({ type: DynamoDBProvisionedThroughputDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => DynamoDBProvisionedThroughputDto)
  @ValidateIf((o) => o.type === 'dynamodb')
  dynamoDBProvisionedThroughput?: DynamoDBProvisionedThroughputDto;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  awsRegion?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  awsAccessKeyId?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  awsSecretAccessKey?: string;
}
export class UpdateDatabaseConnectionDto {
  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  name?: string;

  @ApiPropertyOptional({
    enum: ['mongodb', 'mysql', 'postgresql', 'sqlite', 'dynamodb'],
  })
  @IsOptional()
  @IsEnum(['mongodb', 'mysql', 'postgresql', 'sqlite', 'dynamodb'])
  type?: 'mongodb' | 'mysql' | 'postgresql' | 'sqlite' | 'dynamodb';

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @ValidateIf((o) => o.type !== 'dynamodb' && o.connectionString === undefined)
  host?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsNumber()
  @ValidateIf((o) => o.type !== 'dynamodb' && o.connectionString === undefined)
  port?: number;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  username?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  password?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  databaseName?: string;

  @ApiPropertyOptional({
    description:
      'Complete database connection string. If provided, individual connection details will be updated if present for non-DynamoDB types.',
  })
  @IsOptional()
  @IsString()
  @ValidateIf((o) => o.type !== 'dynamodb')
  connectionString?: string;

  // DynamoDB Specific Fields (Optional)
  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @ValidateIf((o) => o.type === 'dynamodb')
  dynamoDBTableName?: string;

  @ApiPropertyOptional({ type: [DynamoDBKeySchemaElementDto] })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => DynamoDBKeySchemaElementDto)
  @ValidateIf((o) => o.type === 'dynamodb')
  dynamoDBKeySchema?: DynamoDBKeySchemaElementDto[];

  @ApiPropertyOptional({ type: [DynamoDBAttributeDefinitionDto] })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => DynamoDBAttributeDefinitionDto)
  @ValidateIf((o) => o.type === 'dynamodb')
  dynamoDBAttributeDefinitions?: DynamoDBAttributeDefinitionDto[];

  @ApiPropertyOptional({ type: DynamoDBProvisionedThroughputDto })
  @IsOptional()
  @ValidateNested()
  @Type(() => DynamoDBProvisionedThroughputDto)
  @ValidateIf((o) => o.type === 'dynamodb')
  dynamoDBProvisionedThroughput?: DynamoDBProvisionedThroughputDto;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  awsRegion?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  awsAccessKeyId?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  awsSecretAccessKey?: string;
}
