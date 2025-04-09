import { ApiProperty } from '@nestjs/swagger';

export class GeminiContentDto {
  @ApiProperty({
    description: 'The text content to be processed by the Google Gemini model.',
    type: String,
  })
  text: string;
}

export class GeminiContentsDto {
  @ApiProperty({
    description:
      'An array of parts containing the text to be processed by the Gemini model.',
    type: [GeminiContentDto],
  })
  parts: GeminiContentDto[];
}

export class GeminiDto {
  @ApiProperty({
    description:
      'The contents array that contains the text to be processed by the Gemini model.',
    type: [GeminiContentsDto],
  })
  contents: GeminiContentsDto[];
}
