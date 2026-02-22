import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuditLog } from './audit-log.entity';

@Injectable()
export class AuditLogService {
  constructor(
    @InjectRepository(AuditLog)
    private readonly repo: Repository<AuditLog>,
  ) {}

  async log(
    action: string,
    ip: string,
    actor: string,
    details?: string,
  ): Promise<void> {
    const entry = this.repo.create({ action, ip, actor, details });
    await this.repo.save(entry);
  }
}
