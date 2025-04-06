import {
  Injectable,
  OnModuleDestroy,
  OnModuleInit,
  BadRequestException,
  InternalServerErrorException,
} from '@nestjs/common';

import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  async onModuleInit() {
    await this.$connect();
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }
  async handler(model: string, operation: string, data?: any) {
    try {
      if (!model || typeof model !== 'string') {
        throw new BadRequestException(`Invalid model: ${model}`);
      }

      if (!Object.keys(prisma).includes(model)) {
        throw new BadRequestException(
          `Model ${model} does not exist in Prisma Client.`,
        );
      }

      const prismaModel = prisma[model] as any;
      let queryOptions: any = { where: {}, include: {} };

      if (model === 'task') {
        queryOptions.include = {
          Status: {
            select: {
              id: true,
              name: true,
              Color: { select: { id: true, color: true, name: true } },
            },
          },
          Priority: {
            select: {
              id: true,
              name: true,
              Color: { select: { id: true, color: true, name: true } },
            },
          },
          User: { select: { id: true, name: true, image: true } },
        };
      }

      if (model === 'status') {
        queryOptions.include = {
          Color: { select: { id: true, name: true, color: true } },
        };
      }

      if (data?.id) {
        if (model === 'project') {
          queryOptions.include = {
            Task: {
              select: {
                id: true,
                name: true,
                statusId: true,
                Status: {
                  select: {
                    id: true,
                    name: true,
                    Color: { select: { id: true, color: true, name: true } },
                  },
                },
                Priority: {
                  select: {
                    id: true,
                    name: true,
                    Color: { select: { id: true, color: true, name: true } },
                  },
                },
                User: { select: { id: true, name: true, image: true } },
              },
            },
          };
        }
        queryOptions.where = { id: data.id };
      }

      switch (operation) {
        case 'findManyFields':
          return await prismaModel.findMany({
            select: { id: true, name: true },
          });
        case 'findMany':
          return await prismaModel.findMany(queryOptions);
        case 'findFilterMany':
          return await prismaModel.findMany({ where: { pageId: data.pageId } });
        case 'findUnique':
          if (!data?.id)
            throw new BadRequestException(
              'findUnique operation requires an "id".',
            );
          return await prismaModel.findUnique(queryOptions);
        case 'create':
          return await prismaModel.create({ data });
        case 'update':
          if (!data?.id)
            throw new BadRequestException('Update operation requires an "id".');
          return await prismaModel.update({ where: { id: data.id }, data });
        case 'delete':
          if (!data?.id)
            throw new BadRequestException('Delete operation requires an "id".');
          return await prismaModel.delete({ where: { id: data.id } });
        case 'deleteMany':
          if (!data?.ids)
            throw new BadRequestException('Bulk delete requires "ids" array.');
          return await prismaModel.deleteMany({
            where: { id: { in: data.ids } },
          });
        default:
          throw new BadRequestException(`Unsupported operation: ${operation}`);
      }
    } catch (error) {
      console.error('Error in Prisma service:', error);
      throw new InternalServerErrorException(
        'Error executing Prisma operation.',
      );
    }
  }
}
