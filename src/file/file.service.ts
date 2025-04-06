import {
  Injectable,
  NotFoundException,
  InternalServerErrorException,
  Inject,
  BadRequestException,
} from '@nestjs/common';
import * as fs from 'fs-extra';
import * as path from 'path';
import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
} from '@aws-sdk/client-s3';
import { v4 as uuidv4 } from 'uuid';
import { PrismaService } from '../prisma/prisma.service';
import * as dotenv from 'dotenv';
import { REQUEST } from '@nestjs/core';
import { Request, Express } from 'express';
import { Readable } from 'stream';
import { UserPrismaDto } from '../user/dto/';

dotenv.config();
@Injectable()
export class FileService {
  //private readonly basePath = path.join(__dirname, '../storage'); // Base storage path
  private readonly s3 = new S3Client({
    region: process.env.AWS_REGION || 'us-east-1', // Default region if undefined
    credentials: {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID ?? '',
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY ?? '',
    },
  });

  constructor(
    @Inject('EXCLUDED_FOLDERS') private readonly EXCLUDED_FOLDERS: string[],
    private prisma: PrismaService,
    @Inject(REQUEST)
    private readonly request: Request & { user?: UserPrismaDto }, // Ensure TypeScript sees the correct structure
  ) {}
  private readonly bucketName = process.env.S3_BUCKET_NAME; // Bucket name from .env
  private get userId(): string | undefined {
    return this.request.user?.id; // Now TypeScript should recognize `id`
  }
  private getFileTree(dir: string, recursive: boolean = false): any[] {
    if (!fs.existsSync(dir)) return [];

    const files = fs.readdirSync(dir);
    return files
      .filter((file) => !this.EXCLUDED_FOLDERS.includes(file))
      .map((file) => {
        const filePath = path.join(dir, file);
        const isDirectory = fs.statSync(filePath).isDirectory();
        return {
          name: file,
          isDirectory,
          path: filePath,
          type: isDirectory ? 'folder' : 'file',
          children:
            isDirectory && recursive ? this.getFileTree(filePath, true) : null,
        };
      });
  }
  async createFolder(name: string, parentId?: string) {
    if (!this.userId) {
      throw new BadRequestException('User ID is required');
    }
    let path = `/${name}`;

    if (parentId) {
      const parentFolder = await this.prisma.folder.findUnique({
        where: { id: parentId },
      });

      if (!parentFolder) {
        throw new NotFoundException(`Parent folder not found`);
      }

      path = `${parentFolder.path}/${name}`;
    }

    return this.prisma.folder.create({
      data: {
        name,
        path,
        createdById: this.userId, // Ensure it's a string (consider throwing an error if undefined)
        parentId: parentId || null,
      },
    });
  }
  async getFolderByPath(path: string) {
    return this.prisma.folder.findFirst({
      where: {
        path,
        createdById: this.userId, // Ensure user only accesses their own folders
      },
      include: {
        files: {
          select: { id: true, name: true, path: true }, // Select only necessary fields
        },
        children: true, // Include subfolders
      },
    });
  }
  async listFolders(parentId?: string) {
    return this.prisma.folder.findMany({
      where: {
        parentId: parentId || null,
        createdById: this.userId, // Filter by user ID
      },
      include: {
        files: {
          select: { id: true, name: true, path: true }, // Select only the necessary fields
        },
        children: true,
      },
    });
  }
  async createFile(name: string, content: string, folderId?: string) {
    if (!this.userId) {
      throw new BadRequestException('User ID is required');
    }
    // Ensure parent folder exists (if provided)
    if (folderId) {
      const parentFolder = await this.prisma.folder.findUnique({
        where: { id: folderId },
      });
      if (!parentFolder)
        throw new NotFoundException('Parent folder does not exist');
    }

    // Generate a unique file key for S3
    const uniqueId = uuidv4();
    const fileKey = folderId
      ? `${folderId}/${uniqueId}-${name}`
      : `${uniqueId}-${name}`;

    // Upload file to S3
    try {
      await this.s3.send(
        new PutObjectCommand({
          Bucket: this.bucketName,
          Key: fileKey,
          Body: content,
          ContentType: 'text/plain', // Adjust based on file type
        }),
      );
    } catch (error) {
      throw new BadRequestException('Failed to upload file to S3');
    }

    // Save metadata in Prisma database
    const file = await this.prisma.file.create({
      data: {
        name,
        path: `s3://${this.bucketName}/${fileKey}`,
        content, // Optional: Store file content in DB (remove if unnecessary)
        createdById: this.userId, // Filter by user ID
        folderId: folderId || null,
      },
    });

    return { message: 'File uploaded successfully', file };
  }
  async getFile(id: string) {
    // Step 1: Fetch file metadata from Prisma
    const file = await this.prisma.file.findUnique({
      where: { id, createdById: this.userId },
    });

    if (!file) {
      throw new NotFoundException('File not found');
    }

    const fileKey = file.path.replace(`s3://${this.bucketName}/`, '');

    // Step 2: Fetch file content from S3
    try {
      const { Body } = await this.s3.send(
        new GetObjectCommand({
          Bucket: this.bucketName,
          Key: fileKey,
        }),
      );

      // Step 3: Convert the stream into a string
      const streamToString = (stream: Readable): Promise<string> =>
        new Promise((resolve, reject) => {
          const chunks: Buffer[] = [];
          stream.on('data', (chunk) => chunks.push(chunk));
          stream.on('end', () =>
            resolve(Buffer.concat(chunks).toString('utf-8')),
          );
          stream.on('error', reject);
        });

      return {
        name: file.name,
        content: await streamToString(Body as Readable),
      };
    } catch (error) {
      throw new NotFoundException('File could not be retrieved from S3');
    }
  }
  async updateFile(id: string, newName?: string, newContent?: string) {
    const file = await this.prisma.file.findUnique({ where: { id } });

    if (!file) {
      throw new NotFoundException('File not found');
    }

    let updatedPath = file.path;
    let fileKey = file.path.replace(`s3://${this.bucketName}/`, '');

    // If name is changed, generate a new S3 key
    if (newName) {
      const newFileKey = `${uuidv4()}-${newName}`;

      // Copy the old file content to a new file in S3
      try {
        await this.s3.send(
          new PutObjectCommand({
            Bucket: this.bucketName,
            Key: newFileKey,
            Body: newContent || file.content,
            ContentType: 'text/plain',
          }),
        );

        // Delete the old file from S3
        await this.s3.send(
          new DeleteObjectCommand({
            Bucket: this.bucketName,
            Key: fileKey,
          }),
        );

        fileKey = newFileKey;
        updatedPath = `s3://${this.bucketName}/${newFileKey}`;
      } catch (error) {
        throw new BadRequestException('Error updating file in S3');
      }
    } else if (newContent) {
      // Just update the content in S3
      try {
        await this.s3.send(
          new PutObjectCommand({
            Bucket: this.bucketName,
            Key: fileKey,
            Body: newContent,
            ContentType: 'text/plain',
          }),
        );
      } catch (error) {
        throw new BadRequestException('Error updating file content in S3');
      }
    }

    return this.prisma.file.update({
      where: { id },
      data: {
        name: newName || file.name,
        path: updatedPath,
        content: newContent || file.content,
      },
    });
  }
  async deleteFile(id: string) {
    const file = await this.prisma.file.findUnique({ where: { id } });

    if (!file) {
      throw new NotFoundException('File not found');
    }

    const fileKey = file.path.replace(`s3://${this.bucketName}/`, '');

    try {
      // Delete file from S3
      await this.s3.send(
        new DeleteObjectCommand({
          Bucket: this.bucketName,
          Key: fileKey,
        }),
      );

      // Delete metadata from database
      await this.prisma.file.delete({ where: { id } });

      return { message: 'File deleted successfully' };
    } catch (error) {
      throw new BadRequestException('Error deleting file');
    }
  }

  async getFilesByDirectory(
    directory: string = '',
    recursive: boolean = false,
  ): Promise<any> {
    try {
      const directoryPath = directory ? directory : process.cwd();
      return this.getFileTree(directoryPath, recursive);
    } catch (error) {
      return { error: (error as Error).message };
    }
  }

  async getFileContent(filePath: string): Promise<any> {
    try {
      if (!filePath) return { error: 'File path is required' };

      const fileExtension = path.extname(filePath).toLowerCase();
      const imageExtensions = [
        '.png',
        '.jpg',
        '.jpeg',
        '.gif',
        '.bmp',
        '.webp',
      ];

      if (imageExtensions.includes(fileExtension)) {
        const imageData = fs.readFileSync(filePath);
        return { content: imageData.toString('base64'), type: 'image' };
      }

      const fileContent = await fs.promises.readFile(filePath, 'utf-8');
      return { content: fileContent, type: 'text' };
    } catch (error) {
      return { error: (error as Error).message };
    }
  }
  async createOrUpdateFile(
    filePath: string,
    content?: string,
  ): Promise<{ path: string; message: string }> {
    try {
      const resolvedPath = path.resolve(filePath);
      await fs.ensureFile(resolvedPath);
      if (content) {
        await fs.writeFile(resolvedPath, content);
      }
      return {
        path: resolvedPath,
        message: 'File created/updated successfully',
      };
    } catch (error) {
      throw new InternalServerErrorException(
        `Error creating/updating file: ${error.message}`,
      );
    }
  }

  /**
   * Reads a file's contents.
   * @param filePath - Path to the file.
   * @returns File content.
   */
  async readFile(filePath: string): Promise<{ path: string; content: string }> {
    try {
      const resolvedPath = path.resolve(filePath);
      if (!(await fs.pathExists(resolvedPath))) {
        throw new NotFoundException('File not found');
      }
      const content = await fs.readFile(resolvedPath, 'utf8');
      return { path: resolvedPath, content };
    } catch (error) {
      throw new InternalServerErrorException(
        `Error reading file: ${error.message}`,
      );
    }
  }

  /**
   * Deletes a file or directory.
   * @param filePath - Path to the file/folder.
   * @returns Success message.
   */
  async deleteFileOrFolder(
    filePath: string,
  ): Promise<{ path: string; message: string }> {
    try {
      const resolvedPath = path.resolve(filePath);
      if (!(await fs.pathExists(resolvedPath))) {
        throw new NotFoundException('File/Folder not found');
      }
      await fs.remove(resolvedPath);
      return {
        path: resolvedPath,
        message: 'File/Folder deleted successfully',
      };
    } catch (error) {
      throw new InternalServerErrorException(
        `Error deleting file/folder: ${error.message}`,
      );
    }
  }
}
