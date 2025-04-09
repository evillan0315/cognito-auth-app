import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
} from 'typeorm';

@Entity('rds_monitoring')
export class RdsMonitoringEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @CreateDateColumn()
  timestamp: Date;

  @Column('jsonb', { nullable: true })
  instanceInfo: Record<string, any>;

  @Column('jsonb', { nullable: true })
  databaseStats: Record<string, any>;

  @Column('jsonb', { nullable: true })
  connectionPoolStats: Record<string, any>;

  @Column('jsonb', { nullable: true })
  slowQueries: Record<string, any>[];

  @Column({ nullable: true })
  cpuUtilization: number;

  @Column({ nullable: true })
  freeableMemory: number;

  @Column({ nullable: true })
  freeStorageSpace: number;

  @Column({ nullable: true })
  databaseConnections: number;

  @Column({ nullable: true })
  readIOPS: number;

  @Column({ nullable: true })
  writeIOPS: number;

  @Column({ nullable: true })
  readLatency: number;

  @Column({ nullable: true })
  writeLatency: number;

  @Column({ nullable: true })
  readThroughput: number;

  @Column({ nullable: true })
  writeThroughput: number;
}
