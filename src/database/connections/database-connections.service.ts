import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { DatabaseConnectionEntity } from '../entities/database-connection.entity';
import {
  CreateDatabaseConnectionDto,
  UpdateDatabaseConnectionDto,
} from '../dto/database-connection.dto';
import { extractConnectionDetails } from '../../utils/connection-string.util';
@Injectable()
export class DatabaseConnectionsService {
  constructor(
    @InjectRepository(DatabaseConnectionEntity)
    private readonly databaseConnectionRepository: Repository<DatabaseConnectionEntity>,
  ) {}
  async create(
    createDatabaseConnectionDto: CreateDatabaseConnectionDto,
  ): Promise<DatabaseConnectionEntity> {
    let connectionDetails: Partial<DatabaseConnectionEntity> =
      createDatabaseConnectionDto;
    if (createDatabaseConnectionDto.connectionString) {
      connectionDetails = {
        ...createDatabaseConnectionDto,
        ...extractConnectionDetails(
          createDatabaseConnectionDto.connectionString,
          createDatabaseConnectionDto.type,
        ),
      };
    }
    const databaseConnectionEntity =
      this.databaseConnectionRepository.create(connectionDetails);
    return this.databaseConnectionRepository.save(databaseConnectionEntity);
  }

  async findAll(): Promise<DatabaseConnectionEntity[]> {
    return this.databaseConnectionRepository.find();
  }

  async findOne(id: number): Promise<DatabaseConnectionEntity> {
    const databaseConnectionEntity =
      await this.databaseConnectionRepository.findOneBy({ id });
    if (!databaseConnectionEntity) {
      throw new NotFoundException(
        `Database connection with ID ${id} not found`,
      );
    }
    return databaseConnectionEntity;
  }

  async update(
    id: number,
    updateDatabaseConnectionDto: UpdateDatabaseConnectionDto,
  ): Promise<DatabaseConnectionEntity> {
    const existingConnection = await this.findOne(id);
    let updatedDetails: Partial<DatabaseConnectionEntity> =
      updateDatabaseConnectionDto;
    if (updateDatabaseConnectionDto.connectionString) {
      updatedDetails = {
        ...updateDatabaseConnectionDto,
        ...extractConnectionDetails(
          updateDatabaseConnectionDto.connectionString,
          existingConnection.type,
        ),
      };
    }
    this.databaseConnectionRepository.merge(existingConnection, updatedDetails);
    console.log(existingConnection, updatedDetails);
    return this.databaseConnectionRepository.save(existingConnection);
  }

  async remove(id: number): Promise<void> {
    const databaseConnectionEntity = await this.findOne(id);
    await this.databaseConnectionRepository.remove(databaseConnectionEntity);
  }
}
