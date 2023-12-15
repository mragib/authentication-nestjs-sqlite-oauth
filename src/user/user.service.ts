import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './user.entity';
import { Repository } from 'typeorm';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User) private readonly userRepository: Repository<User>,
  ) {}

  async save(body) {
    return this.userRepository.save(body);
  }

  async findOne(data) {
    return await this.userRepository.findOneBy(data);
  }

  async update(id, options) {
    return await this.userRepository.update(id, options);
  }
}
