import { Module } from '@nestjs/common';
import { FileService } from './file.service';
import { FileController } from './file.controller';
import { PrismaModule } from '../prisma/prisma.module'; // Import PrismaModule

@Module({
  imports: [PrismaModule], // 👈 Ensure PrismaModule is imported
  providers: [
    FileService,
    {
      provide: 'EXCLUDED_FOLDERS',
      useValue: ['node_modules', 'dist', '.git'], // Example folders to exclude
    },
  ],
  controllers: [FileController],
  exports: [FileService],
})
export class FileModule {}
