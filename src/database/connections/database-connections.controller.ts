import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Put,
  Delete,
  UseGuards,
} from '@nestjs/common';
import { DatabaseConnectionsService } from './database-connections.service';
import {
  CreateDatabaseConnectionDto,
  UpdateDatabaseConnectionDto,
} from '../dto/database-connection.dto';
import { DatabaseConnectionEntity } from '../entities/database-connection.entity';
import {
  ApiCreatedResponse,
  ApiOkResponse,
  ApiTags,
  ApiParam,
  ApiBody,
  ApiOperation,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { Roles } from '../../admin/roles/roles.decorator'; // Ensure correct path
import { Role } from '../../admin/roles/role.enum'; // Ensure correct path
import { RolesGuard } from '../../admin/roles/roles.guard'; // Ensure correct path
import { CognitoGuard } from '../../aws/cognito/cognito.guard'; // Adjust the path as needed

@ApiTags('Database - Connections') // Updated Swagger grouping
@ApiBearerAuth() // Requires authentication via Bearer token
@UseGuards(CognitoGuard, RolesGuard)
@Controller('api/database/connections')
export class DatabaseConnectionsController {
  constructor(
    private readonly databaseConnectionsService: DatabaseConnectionsService,
  ) {}

  @Post()
  @Roles(Role.ADMIN, Role.SUPERADMIN) // Restrict to Admins
  @ApiOperation({ summary: 'Create a new database connection' })
  @ApiCreatedResponse({
    description: 'The database connection has been successfully created.',
    type: DatabaseConnectionEntity,
  })
  @ApiBody({
    type: CreateDatabaseConnectionDto,
    description:
      'Details for creating a new database connection. You can provide individual connection details (host, port, etc.) or a complete connection string.',
  })
  async create(
    @Body() createDatabaseConnectionDto: CreateDatabaseConnectionDto,
  ): Promise<DatabaseConnectionEntity> {
    return this.databaseConnectionsService.create(createDatabaseConnectionDto);
  }

  @Get()
  @Roles(Role.ADMIN, Role.SUPERADMIN) // Restrict to Admins
  @ApiOperation({ summary: 'Get all database connections' })
  @ApiOkResponse({
    description: 'A list of database connections.',
    type: [DatabaseConnectionEntity],
  })
  async findAll(): Promise<DatabaseConnectionEntity[]> {
    return this.databaseConnectionsService.findAll();
  }

  @Get(':id')
  @Roles(Role.ADMIN, Role.SUPERADMIN) // Restrict to Admins
  @ApiOperation({ summary: 'Get a database connection by ID' })
  @ApiOkResponse({
    description: 'The requested database connection.',
    type: DatabaseConnectionEntity,
  })
  @ApiParam({
    name: 'id',
    type: 'string',
    description: 'ID of the database connection to retrieve.',
  })
  async findOne(@Param('id') id: string): Promise<DatabaseConnectionEntity> {
    return this.databaseConnectionsService.findOne(+id);
  }

  @Put(':id')
  @Roles(Role.ADMIN, Role.SUPERADMIN) // Restrict to Admins
  @ApiOperation({ summary: 'Update an existing database connection' })
  @ApiOkResponse({
    description: 'The database connection has been successfully updated.',
    type: DatabaseConnectionEntity,
  })
  @ApiParam({
    name: 'id',
    type: 'string',
    description: 'ID of the database connection to update.',
  })
  @ApiBody({
    type: UpdateDatabaseConnectionDto,
    description:
      'Details for updating an existing database connection. You can update individual connection details or the complete connection string.',
  })
  async update(
    @Param('id') id: string,
    @Body() updateDatabaseConnectionDto: UpdateDatabaseConnectionDto,
  ): Promise<DatabaseConnectionEntity> {
    return this.databaseConnectionsService.update(
      +id,
      updateDatabaseConnectionDto,
    );
  }

  @Delete(':id')
  @Roles(Role.ADMIN, Role.SUPERADMIN) // Restrict to Admins
  @ApiOperation({ summary: 'Delete a database connection by ID' })
  @ApiOkResponse({
    description: 'The database connection has been successfully deleted.',
  })
  @ApiParam({
    name: 'id',
    type: 'string',
    description: 'ID of the database connection to delete.',
  })
  async remove(@Param('id') id: string): Promise<void> {
    await this.databaseConnectionsService.remove(+id);
  }
}
