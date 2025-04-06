import { SetMetadata } from '@nestjs/common';

// Constant key for storing roles metadata
export const ROLES_KEY = 'roles';

/**
 * Custom decorator to assign roles to a handler or controller
 * @param roles - List of roles to be assigned to a route or controller
 * @returns Metadata for the roles
 */
export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);
