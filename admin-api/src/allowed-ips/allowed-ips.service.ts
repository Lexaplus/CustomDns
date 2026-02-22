import {
  Injectable,
  NotFoundException,
  ConflictException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as net from 'net';
import { AllowedIp } from './allowed-ip.entity';
import { AuditLogService } from '../audit-log/audit-log.service';
import { FirewallService } from '../firewall/firewall.service';

export interface CreateAllowedIpDto {
  ip: string;
  label?: string;
}

export interface UpdateAllowedIpDto {
  enabled?: boolean;
  label?: string;
}

@Injectable()
export class AllowedIpsService {
  constructor(
    @InjectRepository(AllowedIp)
    private readonly repo: Repository<AllowedIp>,
    private readonly auditLog: AuditLogService,
    private readonly firewall: FirewallService,
  ) {}

  async findAll(): Promise<AllowedIp[]> {
    return this.repo.find({ order: { createdAt: 'DESC' } });
  }

  async create(dto: CreateAllowedIpDto, actor: string): Promise<AllowedIp> {
    const ip = this.validateIp(dto.ip);

    const existing = await this.repo.findOne({ where: { ip } });
    if (existing) {
      throw new ConflictException(`IP ${ip} is already in the allowlist`);
    }

    const record = this.repo.create({ ip, label: dto.label, enabled: true });
    const saved = await this.repo.save(record);

    await this.auditLog.log('ADD_IP', ip, actor, dto.label);
    await this.firewall.applyAllowlist();

    return saved;
  }

  async update(
    id: number,
    dto: UpdateAllowedIpDto,
    actor: string,
  ): Promise<AllowedIp> {
    const record = await this.findOrThrow(id);

    if (dto.label !== undefined) record.label = dto.label;
    if (dto.enabled !== undefined) record.enabled = dto.enabled;

    const saved = await this.repo.save(record);

    await this.auditLog.log(
      'UPDATE_IP',
      record.ip,
      actor,
      JSON.stringify(dto),
    );
    await this.firewall.applyAllowlist();

    return saved;
  }

  async remove(id: number, actor: string): Promise<void> {
    const record = await this.findOrThrow(id);
    await this.repo.remove(record);

    await this.auditLog.log('REMOVE_IP', record.ip, actor);
    await this.firewall.applyAllowlist();
  }

  private async findOrThrow(id: number): Promise<AllowedIp> {
    const record = await this.repo.findOne({ where: { id } });
    if (!record) {
      throw new NotFoundException(`AllowedIp with id ${id} not found`);
    }
    return record;
  }

  private validateIp(raw: string): string {
    const trimmed = raw.trim();
    if (!net.isIP(trimmed)) {
      throw new BadRequestException(
        `"${trimmed}" is not a valid IPv4 or IPv6 address`,
      );
    }
    return trimmed;
  }
}
