import {
  Injectable,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
  ) {}

  async create(userData: Partial<User>): Promise<User> {
    if (!userData.email || !userData.password) {
      throw new BadRequestException('Email and password are required');
    }

    const existingUser = await this.usersRepository.findOne({
      where: { email: userData.email },
    });

    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    const hashedPassword = await bcrypt.hash(userData.password, 12);
    const user = this.usersRepository.create({
      ...userData,
      password: hashedPassword,
    });

    return this.usersRepository.save(user);
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.usersRepository.findOne({ where: { email } });
  }

  async findById(id: string): Promise<User | null> {
    return this.usersRepository.findOne({ where: { id } });
  }

  async updateRefreshToken(
    userId: string,
    refreshToken: string | null,
  ): Promise<void> {
    await this.usersRepository.update(userId, {
      refreshToken: refreshToken ?? undefined,
    });
  }
}
