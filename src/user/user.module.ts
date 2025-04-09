import { Module } from '@nestjs/common';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { CognitoModule } from '../aws/cognito/cognito.module';

@Module({
  imports: [CognitoModule], // Import CognitoModule to make CognitoService available
  controllers: [UserController],
  providers: [UserService],
})
export class UserModule {}
