import { ApiProperty } from '@nestjs/swagger';
import { IsArray, IsNotEmpty, IsString, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';

class ParameterDto {
  @ApiProperty({
    description: 'The name of the parameter',
    example: 'max_connections',
  })
  @IsNotEmpty()
  @IsString()
  name: string;

  @ApiProperty({
    description: 'The value of the parameter',
    example: '100',
  })
  @IsNotEmpty()
  @IsString()
  value: string;
}

export class UpdateParametersDto {
  @ApiProperty({
    description: 'List of parameters to update',
    type: [ParameterDto],
  })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => ParameterDto)
  parameters: ParameterDto[];
}
