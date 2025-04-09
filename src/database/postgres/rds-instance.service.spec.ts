import { Test, TestingModule } from '@nestjs/testing';
import { RdsInstanceService } from './rds-instance.service';
import { ConfigService } from '@nestjs/config';
import {
  RDSClient,
  CreateDBInstanceCommand,
  DeleteDBInstanceCommand,
  StopDBInstanceCommand,
  StartDBInstanceCommand,
  DescribeDBInstancesCommand,
  ModifyDBInstanceCommand,
  RebootDBInstanceCommand,
} from '@aws-sdk/client-rds';

// Mock the AWS SDK
jest.mock('@aws-sdk/client-rds', () => {
  return {
    RDSClient: jest.fn().mockImplementation(() => ({
      send: jest.fn(),
    })),
    CreateDBInstanceCommand: jest.fn().mockImplementation((params) => ({
      ...params,
      type: 'CreateDBInstanceCommand',
    })),
    DeleteDBInstanceCommand: jest.fn().mockImplementation((params) => ({
      ...params,
      type: 'DeleteDBInstanceCommand',
    })),
    StopDBInstanceCommand: jest.fn().mockImplementation((params) => ({
      ...params,
      type: 'StopDBInstanceCommand',
    })),
    StartDBInstanceCommand: jest.fn().mockImplementation((params) => ({
      ...params,
      type: 'StartDBInstanceCommand',
    })),
    DescribeDBInstancesCommand: jest.fn().mockImplementation((params) => ({
      ...params,
      type: 'DescribeDBInstancesCommand',
    })),
    ModifyDBInstanceCommand: jest.fn().mockImplementation((params) => ({
      ...params,
      type: 'ModifyDBInstanceCommand',
    })),
    RebootDBInstanceCommand: jest.fn().mockImplementation((params) => ({
      ...params,
      type: 'RebootDBInstanceCommand',
    })),
  };
});

describe('RdsInstanceService', () => {
  let service: RdsInstanceService;
  let configService: ConfigService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RdsInstanceService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              switch (key) {
                case 'AWS_REGION':
                  return 'us-east-1';
                case 'AWS_ACCESS_KEY_ID':
                  return 'test-access-key';
                case 'AWS_SECRET_ACCESS_KEY':
                  return 'test-secret-key';
                case 'NODE_ENV':
                  return 'test';
                default:
                  return undefined;
              }
            }),
          },
        },
      ],
    }).compile();

    service = module.get<RdsInstanceService>(RdsInstanceService);
    configService = module.get<ConfigService>(ConfigService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('createInstance', () => {
    it('should create an RDS instance successfully', async () => {
      const mockResponse = {
        DBInstance: {
          DBInstanceIdentifier: 'test-db',
          DBInstanceStatus: 'creating',
          Engine: 'postgres',
        },
      };

      // Use any to bypass TypeScript's type checking for the test
      (service as any).rdsClient.send = jest
        .fn()
        .mockResolvedValueOnce(mockResponse);

      const result = await service.createInstance({
        dbInstanceIdentifier: 'test-db',
        dbInstanceClass: 'db.t3.micro',
      });

      expect(result).toEqual(mockResponse.DBInstance);
      expect((service as any).rdsClient.send).toHaveBeenCalledTimes(1);
      expect(CreateDBInstanceCommand).toHaveBeenCalledWith(
        expect.objectContaining({
          DBInstanceIdentifier: 'test-db',
          DBInstanceClass: 'db.t3.micro',
          Engine: 'postgres',
        }),
      );
    });

    it('should throw an error when creation fails', async () => {
      // Use any to bypass TypeScript's type checking for the test
      (service as any).rdsClient.send = jest
        .fn()
        .mockRejectedValueOnce(new Error('Creation failed'));

      await expect(
        service.createInstance({ dbInstanceIdentifier: 'test-db' }),
      ).rejects.toThrow('Failed to create RDS instance: Creation failed');
    });
  });

  describe('deleteInstance', () => {
    it('should delete an RDS instance successfully', async () => {
      const mockResponse = {
        DBInstance: {
          DBInstanceIdentifier: 'test-db',
          DBInstanceStatus: 'deleting',
        },
      };

      // Use any to bypass TypeScript's type checking for the test
      (service as any).rdsClient.send = jest
        .fn()
        .mockResolvedValueOnce(mockResponse);

      const result = await service.deleteInstance({
        dbInstanceIdentifier: 'test-db',
        skipFinalSnapshot: true,
      });

      expect(result).toEqual(mockResponse.DBInstance);
      expect((service as any).rdsClient.send).toHaveBeenCalledTimes(1);
      expect(DeleteDBInstanceCommand).toHaveBeenCalledWith(
        expect.objectContaining({
          DBInstanceIdentifier: 'test-db',
          SkipFinalSnapshot: true,
        }),
      );
    });

    it('should throw an error when deletion fails', async () => {
      // Use any to bypass TypeScript's type checking for the test
      (service as any).rdsClient.send = jest
        .fn()
        .mockRejectedValueOnce(new Error('Deletion failed'));

      await expect(
        service.deleteInstance({ dbInstanceIdentifier: 'test-db' }),
      ).rejects.toThrow('Failed to delete RDS instance: Deletion failed');
    });
  });

  describe('stopInstance', () => {
    it('should stop an RDS instance successfully', async () => {
      const mockResponse = {
        DBInstance: {
          DBInstanceIdentifier: 'test-db',
          DBInstanceStatus: 'stopping',
        },
      };

      // Use any to bypass TypeScript's type checking for the test
      (service as any).rdsClient.send = jest
        .fn()
        .mockResolvedValueOnce(mockResponse);

      const result = await service.stopInstance('test-db');

      expect(result).toEqual(mockResponse.DBInstance);
      expect((service as any).rdsClient.send).toHaveBeenCalledTimes(1);
      expect(StopDBInstanceCommand).toHaveBeenCalledWith(
        expect.objectContaining({
          DBInstanceIdentifier: 'test-db',
        }),
      );
    });

    it('should throw an error when stopping fails', async () => {
      // Use any to bypass TypeScript's type checking for the test
      (service as any).rdsClient.send = jest
        .fn()
        .mockRejectedValueOnce(new Error('Stop failed'));

      await expect(service.stopInstance('test-db')).rejects.toThrow(
        'Failed to stop RDS instance: Stop failed',
      );
    });
  });

  describe('startInstance', () => {
    it('should start an RDS instance successfully', async () => {
      const mockResponse = {
        DBInstance: {
          DBInstanceIdentifier: 'test-db',
          DBInstanceStatus: 'starting',
        },
      };

      // Use any to bypass TypeScript's type checking for the test
      (service as any).rdsClient.send = jest
        .fn()
        .mockResolvedValueOnce(mockResponse);

      const result = await service.startInstance('test-db');

      expect(result).toEqual(mockResponse.DBInstance);
      expect((service as any).rdsClient.send).toHaveBeenCalledTimes(1);
      expect(StartDBInstanceCommand).toHaveBeenCalledWith(
        expect.objectContaining({
          DBInstanceIdentifier: 'test-db',
        }),
      );
    });

    it('should throw an error when starting fails', async () => {
      // Use any to bypass TypeScript's type checking for the test
      (service as any).rdsClient.send = jest
        .fn()
        .mockRejectedValueOnce(new Error('Start failed'));

      await expect(service.startInstance('test-db')).rejects.toThrow(
        'Failed to start RDS instance: Start failed',
      );
    });
  });

  describe('getInstance', () => {
    it('should get RDS instance details successfully', async () => {
      const mockResponse = {
        DBInstances: [
          {
            DBInstanceIdentifier: 'test-db',
            DBInstanceStatus: 'available',
            Engine: 'postgres',
          },
        ],
      };

      // Use any to bypass TypeScript's type checking for the test
      (service as any).rdsClient.send = jest
        .fn()
        .mockResolvedValueOnce(mockResponse);

      const result = await service.getInstance('test-db');

      expect(result).toEqual(mockResponse.DBInstances[0]);
      expect((service as any).rdsClient.send).toHaveBeenCalledTimes(1);
      expect(DescribeDBInstancesCommand).toHaveBeenCalledWith(
        expect.objectContaining({
          DBInstanceIdentifier: 'test-db',
        }),
      );
    });

    it('should throw an error when instance is not found', async () => {
      // Use any to bypass TypeScript's type checking for the test
      (service as any).rdsClient.send = jest
        .fn()
        .mockResolvedValueOnce({ DBInstances: [] });

      await expect(service.getInstance('test-db')).rejects.toThrow(
        'RDS instance not found: test-db',
      );
    });
  });

  describe('listInstances', () => {
    it('should list all PostgreSQL RDS instances', async () => {
      const mockResponse = {
        DBInstances: [
          {
            DBInstanceIdentifier: 'postgres-db-1',
            Engine: 'postgres',
          },
          {
            DBInstanceIdentifier: 'postgres-db-2',
            Engine: 'postgres',
          },
          {
            DBInstanceIdentifier: 'mysql-db',
            Engine: 'mysql',
          },
        ],
      };

      // Use any to bypass TypeScript's type checking for the test
      (service as any).rdsClient.send = jest
        .fn()
        .mockResolvedValueOnce(mockResponse);

      const result = await service.listInstances();

      expect(result).toHaveLength(2); // Only PostgreSQL instances
      expect(result[0].DBInstanceIdentifier).toBe('postgres-db-1');
      expect(result[1].DBInstanceIdentifier).toBe('postgres-db-2');
      expect((service as any).rdsClient.send).toHaveBeenCalledTimes(1);
    });
  });
});
