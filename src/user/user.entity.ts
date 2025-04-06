import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';

@Entity('users')
export class User {
  @ApiProperty({
    example: 'd290f1ee-6c54-4b01-90e6-d701748f0851',
    description: 'The unique ID of the user',
  })
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ApiProperty({ example: 'johndoe', description: 'The username of the user' })
  @Column({ unique: true })
  username: string;

  @ApiProperty({ example: 'John', description: 'First name of the user' })
  @Column()
  firstName: string;

  @ApiProperty({ example: 'Doe', description: 'Last name of the user' })
  @Column()
  lastName: string;

  @ApiProperty({
    example: 'john.doe@example.com',
    description: 'Email address of the user',
  })
  @Column({ unique: true })
  email: string;

  @ApiProperty({ example: true, description: 'Whether the user is active' })
  @Column({ default: true })
  isActive: boolean;

  @ApiProperty({
    example: 'admin',
    description: 'Role of the user (e.g. user, admin, superadmin)',
  })
  @Column({ default: 'user' })
  role: string;

  @ApiProperty({
    example: '2025-04-04T12:34:56.789Z',
    description: 'Date the user was created',
  })
  @CreateDateColumn()
  createdAt: Date;

  @ApiProperty({
    example: '2025-04-05T08:21:43.321Z',
    description: 'Date the user was last updated',
  })
  @UpdateDateColumn()
  updatedAt: Date;
}
