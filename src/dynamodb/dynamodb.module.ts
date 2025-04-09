import { Module } from '@nestjs/common';
import { DynamodbController } from './dynamodb.controller';
import { DynamodbService } from './dynamodb.service';

@Module({
  controllers: [DynamodbController],
  providers: [DynamodbService],
  exports: [DynamodbService], // 👈 Export it for use in other modules
})
export class DynamodbModule {}
