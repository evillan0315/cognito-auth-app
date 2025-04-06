import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { RolesModule } from './admin/roles/roles.module';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { GoogleStrategy } from './auth/strategies/google.strategy';
import { AwsModule } from './aws/aws.module';
import { AdminModule } from './admin/admin.module';
import { CognitoModule } from './aws/cognito/cognito.module'; // 👈 Add CognitoModule here
import { FileModule } from './file/file.module';
import { PrismaModule } from './prisma/prisma.module';
import { TerminalModule } from './terminal/terminal.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),
    TypeOrmModule.forRoot({
      type: 'postgres',
      url: process.env.DATABASE_URL,
      entities: [], // Add your entities here
      synchronize: true,
    }),
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'default_secret_key',
      signOptions: { expiresIn: '1h' },
    }),
    PassportModule.register({ defaultStrategy: 'jwt' }),

    // Feature modules
    AuthModule,
    UserModule,
    RolesModule,
    AwsModule,
    AdminModule,
    CognitoModule,
    FileModule,
    TerminalModule,
    PrismaModule, // 👈 Now Cognito is fully integrated
  ],
  controllers: [AppController],
  providers: [AppService, GoogleStrategy],
})
export class AppModule {}
