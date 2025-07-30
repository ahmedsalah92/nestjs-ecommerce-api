import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { Exclude } from 'class-transformer';

export enum UserRole {
  CUSTOMER = 'customer',
  VENDOR = 'vendor',
  ADMIN = 'admin',
}

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column()
  firstName: string;

  @Column()
  lastName: string;

  @Column()
  @Exclude()
  password: string;

  @Column({
    type: 'text',
    default: UserRole.CUSTOMER,
  })
  role: UserRole;

  @Column({ default: false })
  isEmailVerified: boolean;

  @Column({ nullable: true })
  emailVerificationToken: string;

  @Column({ nullable: true })
  @Exclude()
  refreshToken: string;

  @Column({ nullable: true })
  profileImage: string; // Will store file path/URL (AWS S3 later)

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
