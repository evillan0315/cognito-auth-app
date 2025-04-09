import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { PostgresService } from './postgres.service';
import { RdsBackupService } from './rds-backup.service';
import { RdsParameterService } from './rds-parameter.service';
import { RdsInstanceService } from './rds-instance.service';
import { PostgresMaintenanceService } from './postgres-maintenance.service';
import { PostgresController } from './postgres.controller';
import { RdsInstanceController } from './rds-instance.controller';
import { ScheduleModule } from '@nestjs/schedule';

@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      name: 'rds', // Named connection for RDS
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        // Use DATABASE_URL if available, otherwise use individual connection parameters
        const databaseUrl = configService.get<string>('DATABASE_URL');

        // Base configuration with common settings
        const baseConfig = {
          type: 'postgres' as const,
          entities: [__dirname + '/../../**/*.entity{.ts,.js}'],
          synchronize: configService.get('NODE_ENV') !== 'production',
          // AWS RDS specific configurations
          ssl:
            configService.get('NODE_ENV') === 'production'
              ? {
                  rejectUnauthorized: false,
                  ca: configService.get('RDS_CA_CERT'),
                }
              : false,
          extra: {
            // Connection pool settings
            max: configService.get('DB_POOL_MAX') || 20, // Maximum number of connections
            min: configService.get('DB_POOL_MIN') || 5, // Minimum number of connections
            idle: configService.get('DB_POOL_IDLE') || 10000, // Max idle time in ms
            // AWS RDS specific settings
            statement_timeout: 30000, // Statement timeout in ms
            query_timeout: 30000, // Query timeout in ms
            connectionTimeoutMillis: 10000, // Connection timeout
            keepAlive: true, // Keep connections alive
            keepAliveInitialDelayMillis: 10000, // Delay before sending keep-alive
          },
          logging: configService.get('NODE_ENV') !== 'production',
          // Auto-reconnect on connection loss
          retryAttempts: 5,
          retryDelay: 3000,
        };

        // If DATABASE_URL is provided, use it instead of individual connection parameters
        if (databaseUrl) {
          return {
            ...baseConfig,
            url: databaseUrl,
          } as any;
        }

        // Otherwise, use individual connection parameters
        return {
          ...baseConfig,
          host: configService.get('RDS_HOST') || 'localhost',
          port: parseInt(configService.get('RDS_PORT') || '5432', 10),
          username: configService.get('RDS_USER') || 'postgres',
          password: configService.get('RDS_PASSWORD') || '',
          database: configService.get('RDS_DB') || 'postgres',
        } as any;
      },
    }),
    ScheduleModule.forRoot(),
  ],
  controllers: [PostgresController, RdsInstanceController],
  providers: [
    PostgresService,
    RdsBackupService,
    RdsParameterService,
    RdsInstanceService,
    PostgresMaintenanceService,
  ],
  exports: [
    PostgresService,
    RdsBackupService,
    RdsParameterService,
    RdsInstanceService,
  ],
})
export class PostgresModule {}
