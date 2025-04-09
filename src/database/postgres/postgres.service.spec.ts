import { Test, TestingModule } from '@nestjs/testing';
import { PostgresService } from './postgres.service';
import { ConfigService } from '@nestjs/config';
import { getConnectionToken } from '@nestjs/typeorm';

describe('PostgresService', () => {
  let service: PostgresService;
  let configService: ConfigService;

  const mockConnection = {
    query: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PostgresService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              if (key === 'NODE_ENV') return 'test';
              return 'mock-value';
            }),
          },
        },
        {
          provide: getConnectionToken('rds'),
          useValue: mockConnection,
        },
      ],
    }).compile();

    service = module.get<PostgresService>(PostgresService);
    configService = module.get<ConfigService>(ConfigService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('checkHealth', () => {
    it('should return true when database is healthy', async () => {
      mockConnection.query.mockResolvedValueOnce([{ '?column?': 1 }]);

      const result = await service.checkHealth();

      expect(result).toBe(true);
      expect(mockConnection.query).toHaveBeenCalledWith('SELECT 1');
    });

    it('should return false when database check fails', async () => {
      mockConnection.query.mockRejectedValueOnce(
        new Error('Connection failed'),
      );

      const result = await service.checkHealth();

      expect(result).toBe(false);
      expect(mockConnection.query).toHaveBeenCalledWith('SELECT 1');
    });
  });

  describe('executeQuery', () => {
    it('should execute a query and return results', async () => {
      const mockResults = [{ id: 1, name: 'Test' }];
      mockConnection.query.mockResolvedValueOnce(mockResults);

      const result = await service.executeQuery('SELECT * FROM test');

      expect(result).toEqual(mockResults);
      expect(mockConnection.query).toHaveBeenCalledWith(
        'SELECT * FROM test',
        [],
      );
    });

    it('should throw an error when query fails', async () => {
      mockConnection.query.mockRejectedValueOnce(new Error('Query failed'));

      await expect(service.executeQuery('SELECT * FROM test')).rejects.toThrow(
        'Failed to execute query: Query failed',
      );
    });
  });
});
