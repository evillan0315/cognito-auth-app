import { Module, Global } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { CognitoModule } from './cognito/cognito.module';
import { AwsBillingService } from './aws-billing.service';
import { AwsBillingController } from './aws-billing.controller';

@Global() // Makes this module global
@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true, // Makes the config accessible throughout the app
    }),
    CognitoModule, // Import the Cognito module
  ],
  controllers: [AwsBillingController], // Add the AWS Billing controller
  providers: [AwsBillingService], // Add the AWS Billing service
  exports: [AwsBillingService], // Export the service for use in other modules
})
export class AwsModule {}
