import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from './roles.decorator'; // Ensure this constant is imported

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    // Extract required roles from metadata using the Reflector
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );

    // If no roles are defined for the handler or class, allow access
    if (!requiredRoles) {
      return true;
    }

    // Extract the user from the request
    const { user } = context.switchToHttp().getRequest();
    console.log(user, 'user RolesGuard');
    // If there is no user (i.e., they are not authenticated), deny access
    if (!user) {
      return false;
    }

    // Check if the user's role is in the required roles
    return requiredRoles.includes(user?.role);
  }
}
