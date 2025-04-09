import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PostgresService } from './postgres.service';
import { RdsBackupService } from './rds-backup.service';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class PostgresMaintenanceService {
  private readonly logger = new Logger(PostgresMaintenanceService.name);

  constructor(
    private readonly postgresService: PostgresService,
    private readonly rdsBackupService: RdsBackupService,
    private readonly configService: ConfigService,
  ) {}

  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async runVacuum() {
    this.logger.log('Running VACUUM ANALYZE');
    try {
      await this.postgresService.executeQuery('VACUUM ANALYZE');
      this.logger.log('VACUUM ANALYZE completed successfully');
    } catch (error) {
      this.logger.error(`VACUUM ANALYZE failed: ${error.message}`, error.stack);
    }
  }

  @Cron(CronExpression.EVERY_WEEK)
  async createWeeklySnapshot() {
    if (this.configService.get('NODE_ENV') === 'production') {
      const snapshotId = `weekly-${new Date().toISOString().split('T')[0]}`;
      this.logger.log(`Creating weekly snapshot: ${snapshotId}`);

      try {
        await this.rdsBackupService.createSnapshot(snapshotId);
        this.logger.log(`Weekly snapshot created: ${snapshotId}`);
      } catch (error) {
        this.logger.error(
          `Weekly snapshot failed: ${error.message}`,
          error.stack,
        );
      }
    }
  }

  @Cron(CronExpression.EVERY_DAY_AT_1AM)
  async monitorSlowQueries() {
    this.logger.log('Monitoring slow queries');
    try {
      const slowQueries = await this.postgresService.getSlowQueries();

      if (slowQueries.length > 0) {
        this.logger.warn(`Found ${slowQueries.length} slow queries`);
        // You could send these to a monitoring system or alert via email
      }
    } catch (error) {
      this.logger.error(
        `Slow query monitoring failed: ${error.message}`,
        error.stack,
      );
    }
  }
}
