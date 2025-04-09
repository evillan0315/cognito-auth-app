import { Test, TestingModule } from '@nestjs/testing';
import { RdsBackupService } from './rds-backup.service';
import { ConfigService } from '@nestjs/config';

// Mock the AWS SDK
jest.mock('@aws-sdk/client-rds', () => {
  return {
    RDSClient: jest.fn().mockImplementation(() => ({
      send: jest.fn(),
    })),
    CreateDBSnapshotCommand: jest.fn().mockImplementation((params) => ({
      ...params,
      type: 'CreateDBSnapshotCommand',
    })),
    DescribeDBSnapshotsCommand: jest.fn().mockImplementation((params) => ({
      ...params,
      type: 'DescribeDBSnapshotsCommand',
    })),
  };
});

describe('RdsBackupService', () => {
  let service: RdsBackupService;
  let configService: ConfigService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RdsBackupService,
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
                case 'RDS_INSTANCE_ID':
                  return 'test-db-instance';
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

    service = module.get<RdsBackupService>(RdsBackupService);
    configService = module.get<ConfigService>(ConfigService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('createSnapshot', () => {
    it('should create a snapshot successfully', async () => {
      const mockResponse = {
        DBSnapshot: {
          DBSnapshotIdentifier: 'test-snapshot',
          DBInstanceIdentifier: 'test-db-instance',
          Status: 'creating',
        },
      };

      // Use any to bypass TypeScript's type checking for the test
      (service as any).rdsClient.send = jest
        .fn()
        .mockResolvedValueOnce(mockResponse);

      const result = await service.createSnapshot('test-snapshot');

      expect(result).toEqual(mockResponse);
      expect((service as any).rdsClient.send).toHaveBeenCalledTimes(1);
    });

    it('should throw an error when snapshot creation fails', async () => {
      // Use any to bypass TypeScript's type checking for the test
      (service as any).rdsClient.send = jest
        .fn()
        .mockRejectedValueOnce(new Error('Snapshot creation failed'));

      await expect(service.createSnapshot('test-snapshot')).rejects.toThrow(
        'Failed to create database snapshot: Snapshot creation failed',
      );
    });
  });

  describe('listSnapshots', () => {
    it('should list snapshots successfully', async () => {
      const mockResponse = {
        DBSnapshots: [
          {
            DBSnapshotIdentifier: 'test-snapshot-1',
            DBInstanceIdentifier: 'test-db-instance',
            Status: 'available',
          },
          {
            DBSnapshotIdentifier: 'test-snapshot-2',
            DBInstanceIdentifier: 'test-db-instance',
            Status: 'available',
          },
        ],
      };

      // Use any to bypass TypeScript's type checking for the test
      (service as any).rdsClient.send = jest
        .fn()
        .mockResolvedValueOnce(mockResponse);

      const result = await service.listSnapshots();

      expect(result).toEqual(mockResponse.DBSnapshots);
      expect((service as any).rdsClient.send).toHaveBeenCalledTimes(1);
    });

    it('should throw an error when listing snapshots fails', async () => {
      // Use any to bypass TypeScript's type checking for the test
      (service as any).rdsClient.send = jest
        .fn()
        .mockRejectedValueOnce(new Error('Listing snapshots failed'));

      await expect(service.listSnapshots()).rejects.toThrow(
        'Failed to list database snapshots: Listing snapshots failed',
      );
    });
  });
});
