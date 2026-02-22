import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AllowedIpsModule } from './allowed-ips/allowed-ips.module';
import { AllowedIp } from './allowed-ips/allowed-ip.entity';
import { AuditLog } from './audit-log/audit-log.entity';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'postgres',
      url: process.env.DATABASE_URL,
      entities: [AllowedIp, AuditLog],
      synchronize: true, // demo only — auto-creates tables
      logging: false,
      ssl: false,
    }),
    AllowedIpsModule,
  ],
})
export class AppModule {}
