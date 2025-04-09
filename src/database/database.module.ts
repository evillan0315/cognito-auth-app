import { Module } from '@nestjs/common';
import { DatabaseController } from './database.controller';
import { DatabaseService } from './database.service';
import { DatabaseConnectionsModule } from './connections/database-connections.module';
import { PostgresModule } from './postgres/postgres.module';

@Module({
  imports: [DatabaseConnectionsModule, PostgresModule],
  controllers: [DatabaseController],
  providers: [DatabaseService],
  exports: [DatabaseService, PostgresModule],
})
export class DatabaseModule {}
