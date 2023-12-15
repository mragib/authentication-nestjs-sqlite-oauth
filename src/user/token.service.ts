import { Injectable } from '@nestjs/common';
import { Token } from './token.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

@Injectable()
export class TokenService {
  constructor(
    @InjectRepository(Token)
    private readonly tokenRepository: Repository<Token>,
  ) {}

  async save(body) {
    return this.tokenRepository.save(body);
  }

  async findOne(condition) {
    return this.tokenRepository.findOneBy(condition);
  }

  async delete(condition) {
    return await this.tokenRepository.delete(condition);
  }
}
