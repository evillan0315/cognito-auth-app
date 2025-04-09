import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity()
export class DatabaseConnectionEntity {
  // Make sure the class name matches your import
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @Column()
  type: 'mongodb' | 'mysql' | 'postgresql' | 'sqlite' | 'dynamodb'; // <--- ADD 'dynamodb' HERE

  @Column({ nullable: true })
  host?: string;

  @Column({ nullable: true })
  port?: number;

  @Column({ nullable: true })
  username?: string;

  @Column({ nullable: true })
  password?: string;

  @Column({ nullable: true })
  databaseName?: string;

  @Column({ type: 'text', nullable: true })
  connectionString?: string;

  @Column({ nullable: true })
  dynamoDBTableName?: string;

  @Column({ type: 'jsonb', nullable: true })
  dynamoDBKeySchema?: any; // Use appropriate type if defined

  @Column({ type: 'jsonb', nullable: true })
  dynamoDBAttributeDefinitions?: any; // Use appropriate type if defined

  @Column({ type: 'jsonb', nullable: true })
  dynamoDBProvisionedThroughput?: any; // Use appropriate type if defined

  @Column({ nullable: true })
  awsRegion?: string;

  @Column({ nullable: true })
  awsAccessKeyId?: string;

  @Column({ nullable: true })
  awsSecretAccessKey?: string;
}
