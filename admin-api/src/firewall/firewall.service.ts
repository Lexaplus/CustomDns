import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AllowedIp } from '../allowed-ips/allowed-ip.entity';
import { execFile } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs/promises';
import * as path from 'path';

const execFileAsync = promisify(execFile);

const ALLOWLIST_PATH = '/deploy/allowlist.txt';
const FIREWALL_SCRIPT = '/deploy/firewall_apply.sh';
const LOCK_PATH = '/deploy/firewall.lock';

@Injectable()
export class FirewallService {
  private readonly logger = new Logger(FirewallService.name);

  constructor(
    @InjectRepository(AllowedIp)
    private readonly allowedIpRepo: Repository<AllowedIp>,
  ) {}

  async applyAllowlist(): Promise<void> {
    // Acquire a simple file-based lock to prevent concurrent executions
    const lockFd = await this.acquireLock();
    try {
      await this.writeAllowlist();
      await this.runFirewallScript();
    } finally {
      await this.releaseLock(lockFd);
    }
  }

  private async writeAllowlist(): Promise<void> {
    const ips = await this.allowedIpRepo.find({ where: { enabled: true } });
    const content = ips.map((r) => r.ip).join('\n') + (ips.length ? '\n' : '');

    await fs.mkdir(path.dirname(ALLOWLIST_PATH), { recursive: true });
    await fs.writeFile(ALLOWLIST_PATH, content, 'utf8');
    this.logger.log(`Wrote ${ips.length} IPs to ${ALLOWLIST_PATH}`);
  }

  private async runFirewallScript(): Promise<void> {
    try {
      const { stdout, stderr } = await execFileAsync('sudo', [
        FIREWALL_SCRIPT,
        'update',
      ]);
      if (stdout) this.logger.log(`firewall_apply.sh: ${stdout.trim()}`);
      if (stderr) this.logger.warn(`firewall_apply.sh stderr: ${stderr.trim()}`);
    } catch (err: any) {
      this.logger.error(`firewall_apply.sh failed: ${err.message}`);
      throw new Error(`Firewall script failed: ${err.message}`);
    }
  }

  private async acquireLock(): Promise<fs.FileHandle> {
    const maxWaitMs = 10_000;
    const start = Date.now();

    while (Date.now() - start < maxWaitMs) {
      try {
        // O_CREAT | O_EXCL — atomic create; fails if file exists
        const fd = await fs.open(LOCK_PATH, 'wx');
        return fd;
      } catch {
        // Lock held by another process; wait and retry
        await new Promise((r) => setTimeout(r, 200));
      }
    }
    throw new Error('Could not acquire firewall lock after 10s');
  }

  private async releaseLock(fd: fs.FileHandle): Promise<void> {
    try {
      await fd.close();
      await fs.unlink(LOCK_PATH);
    } catch (err: any) {
      this.logger.warn(`Failed to release lock: ${err.message}`);
    }
  }
}
