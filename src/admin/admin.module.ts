import { Module } from '@nestjs/common';
import { AdminController } from './admin.controller';
import { AdminService } from './admin.service';
import { RolesGuard } from './roles/roles.guard'; // Assuming the guard is at the roles folder
import { RolesController } from './roles/roles.controller';
import { RolesService } from './roles/roles.service';
import { RolesModule } from './roles/roles.module';

@Module({
  imports: [RolesModule], // Import the Roles module if needed
  controllers: [AdminController, RolesController],
  providers: [AdminService, RolesGuard, RolesService], // Provide the RolesGuard here if it's global
})
export class AdminModule {}
