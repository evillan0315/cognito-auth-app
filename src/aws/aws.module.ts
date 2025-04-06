import { Module, Global } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { CognitoModule } from './cognito/cognito.module';

@Global() // Makes this module global
@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true, // Makes the config accessible throughout the app
    }),
    CognitoModule, // Import the Cognito module
  ],
  exports: [CognitoModule], // Export Cognito module for use in other modules
})
export class AwsModule {}
