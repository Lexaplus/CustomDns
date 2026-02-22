import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AllowedIp } from './allowed-ip.entity';
import { AuditLog } from '../audit-log/audit-log.entity';
import { AllowedIpsController } from './allowed-ips.controller';
import { AllowedIpsService } from './allowed-ips.service';
import { AuditLogService } from '../audit-log/audit-log.service';
import { FirewallService } from '../firewall/firewall.service';

@Module({
  imports: [TypeOrmModule.forFeature([AllowedIp, AuditLog])],
  controllers: [AllowedIpsController],
  providers: [AllowedIpsService, AuditLogService, FirewallService],
})
export class AllowedIpsModule {}
