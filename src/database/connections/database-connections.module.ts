// src/database/connections/database-connections.module.ts
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DatabaseConnectionsService } from './database-connections.service';
import { DatabaseConnectionsController } from './database-connections.controller';
import { DatabaseConnectionEntity } from '../entities/database-connection.entity'; // Adjust the path if necessary

@Module({
  imports: [TypeOrmModule.forFeature([DatabaseConnectionEntity])], // <--- THIS IS ALSO IMPORTANT
  providers: [DatabaseConnectionsService],
  controllers: [DatabaseConnectionsController],
  exports: [DatabaseConnectionsService], // If other modules need this service
})
export class DatabaseConnectionsModule {}
