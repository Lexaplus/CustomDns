import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  ParseIntPipe,
  Headers,
  UnauthorizedException,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  AllowedIpsService,
  CreateAllowedIpDto,
  UpdateAllowedIpDto,
} from './allowed-ips.service';
import { IsString, IsOptional, IsBoolean, IsNotEmpty } from 'class-validator';

class CreateIpBody implements CreateAllowedIpDto {
  @IsString()
  @IsNotEmpty()
  ip: string;

  @IsString()
  @IsOptional()
  label?: string;
}

class UpdateIpBody implements UpdateAllowedIpDto {
  @IsBoolean()
  @IsOptional()
  enabled?: boolean;

  @IsString()
  @IsOptional()
  label?: string;
}

@Controller()
export class AllowedIpsController {
  constructor(private readonly service: AllowedIpsService) {}

  // ── Unauthenticated ──────────────────────────────────────────
  @Get('health')
  health() {
    return { status: 'ok', timestamp: new Date().toISOString() };
  }

  // ── Protected endpoints ──────────────────────────────────────
  @Get('allowed-ips')
  async list(@Headers('x-admin-token') token: string) {
    this.assertAuth(token);
    return this.service.findAll();
  }

  @Post('allowed-ips')
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Headers('x-admin-token') token: string,
    @Headers('x-actor') actor: string,
    @Body() body: CreateIpBody,
  ) {
    this.assertAuth(token);
    return this.service.create(body, actor ?? 'api');
  }

  @Patch('allowed-ips/:id')
  async update(
    @Headers('x-admin-token') token: string,
    @Headers('x-actor') actor: string,
    @Param('id', ParseIntPipe) id: number,
    @Body() body: UpdateIpBody,
  ) {
    this.assertAuth(token);
    return this.service.update(id, body, actor ?? 'api');
  }

  @Delete('allowed-ips/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(
    @Headers('x-admin-token') token: string,
    @Headers('x-actor') actor: string,
    @Param('id', ParseIntPipe) id: number,
  ) {
    this.assertAuth(token);
    await this.service.remove(id, actor ?? 'api');
  }

  private assertAuth(token: string): void {
    const expected = process.env.ADMIN_API_TOKEN;
    if (!expected || token !== expected) {
      throw new UnauthorizedException('Invalid or missing x-admin-token');
    }
  }
}
