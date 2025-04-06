import { Module, forwardRef } from '@nestjs/common';
import { PrismaService } from './prisma.service';
import { PrismaController } from './prisma.controller';
import { AuthModule } from '../auth/auth.module'; // ✅ Only use forwardRef once

@Module({
  imports: [forwardRef(() => AuthModule)], // ✅ Keep only forwardRef
  controllers: [PrismaController],
  providers: [PrismaService], // ❌ Removed ApiKeyAuthGuard (it belongs in AuthModule)
  exports: [PrismaService],
})
export class PrismaModule {}
