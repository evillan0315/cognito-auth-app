import { Module } from '@nestjs/common';
import { TerminalGateway } from './terminal.gateway';
import { DynamodbModule } from '../dynamodb/dynamodb.module';
import { CognitoModule } from '../aws/cognito/cognito.module';

@Module({
  imports: [
    DynamodbModule,
    CognitoModule, // Import CognitoModule to make CognitoService available
  ],
  providers: [TerminalGateway],
})
export class TerminalModule {}
