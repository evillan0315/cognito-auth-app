import {
  Controller,
  Post,
  Get,
  Delete,
  Body,
  Query,
  UseGuards,
  Param,
  Res,
  StreamableFile,
  Header,
  Patch,
  Req,
  UseInterceptors,
  UploadedFile,
} from '@nestjs/common';
import { FileService } from './file.service';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  ApiTags,
  ApiOperation,
  ApiQuery,
  ApiBody,
  ApiResponse,
  ApiBearerAuth,
  ApiConsumes,
} from '@nestjs/swagger';
import { Response, Request, Express } from 'express';
import * as fs from 'fs';
import * as path from 'path';
import { diskStorage } from 'multer';

import { RolesGuard } from '../admin/roles/roles.guard'; // Ensure correct path
import { CognitoGuard } from '../aws/cognito/cognito.guard'; // Adjust the path as needed
@ApiTags('File Management') // Updated Swagger grouping
@ApiBearerAuth() // Requires authentication via Bearer token
@UseGuards(CognitoGuard, RolesGuard)
@Controller('api/file')
export class FileController {
  constructor(private readonly fileService: FileService) {}

  @Post('folder')
  @ApiOperation({ summary: 'Create a new folder' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        name: { type: 'string', example: 'My New Folder' },
        parentId: { type: 'string', nullable: true, example: 'folder-67890' },
      },
      required: ['name'],
    },
  })
  @ApiResponse({ status: 201, description: 'Folder created successfully' })
  @ApiResponse({ status: 400, description: 'Invalid request' })
  async createFolder(@Body() body: { name: string; parentId?: string }) {
    return await this.fileService.createFolder(body.name, body.parentId);
  }

  @Get('folder')
  @ApiOperation({ summary: 'List folders' })
  @ApiQuery({
    name: 'parentId',
    required: false,
    description: 'Optional parent folder ID',
    example: 'folder-67890',
  })
  @ApiResponse({ status: 200, description: 'List of folders' })
  async listFolders(@Query('parentId') parentId?: string) {
    return await this.fileService.listFolders(parentId);
  }
  @Get('folder:path')
  @ApiOperation({ summary: 'Get folder contents by path' })
  @ApiResponse({ status: 200, description: 'List of folders and files' })
  async getFolderByPath(@Param('path') path: string, @Req() req: Request) {
    return await this.fileService.getFolderByPath(`/${path}`);
  }
  @Get('raw/:filePath')
  async getFile(
    @Param('filePath') filePath: string,
    @Res() res: Response,
  ): Promise<any> {
    try {
      if (!fs.existsSync(filePath)) {
        return res.status(404).send('File not found');
      }

      const fileExtension = path.extname(filePath).toLowerCase();
      const mimeTypes: Record<string, string> = {
        '.txt': 'text/plain',
        '.json': 'application/json',
        '.html': 'text/html',
        '.css': 'text/css',
        '.js': 'application/javascript',
        '.ts': 'application/typescript',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.gif': 'image/gif',
        '.bmp': 'image/bmp',
        '.webp': 'image/webp',
      };

      const mimeType = mimeTypes[fileExtension] || 'application/octet-stream';

      res.setHeader('Content-Type', mimeType);
      const fileStream = fs.createReadStream(filePath);
      return fileStream.pipe(res);
    } catch (error) {
      return res.status(500).send('Error reading file');
    }
  }
  @Get('list')
  @ApiOperation({ summary: 'List files in a directory' })
  @ApiQuery({
    name: 'directory',
    required: false,
    description: 'Path to the directory',
  })
  @ApiQuery({
    name: 'recursive',
    required: false,
    type: Boolean,
    description: 'List files recursively',
  })
  @ApiResponse({ status: 200, description: 'List of files and directories' })
  async getFiles(
    @Query('directory') directory?: string,
    @Query('recursive') recursive: boolean = false,
  ) {
    return this.fileService.getFilesByDirectory(directory, recursive);
  }

  @Get('content')
  @ApiOperation({ summary: 'Get file content' })
  @ApiQuery({
    name: 'filePath',
    required: true,
    description: 'Path to the file',
  })
  @ApiResponse({
    status: 200,
    description: 'File content returned successfully',
  })
  async getFileContent(@Query('filePath') filePath: string) {
    return this.fileService.getFileContent(filePath);
  }

  @Post('create')
  @ApiOperation({ summary: 'Create a new file' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        name: { type: 'string', example: 'document.txt' },
        content: { type: 'string', example: 'Hello, world!' },
        parentId: { type: 'string', nullable: true, example: 'folder-67890' },
      },
      required: ['name', 'content'], // 'createdById' is not required in the request
    },
  })
  @ApiResponse({ status: 201, description: 'File created successfully' })
  @ApiResponse({ status: 400, description: 'Invalid request' })
  async createFile(
    @Body() body: { name: string; content: string; parentId?: string },
  ) {
    return await this.fileService.createFile(
      body.name,
      body.content,
      body.parentId,
    );
  }

  @Get(':id')
  @ApiOperation({ summary: 'Retrieve a file by ID' })
  @ApiResponse({ status: 200, description: 'File retrieved successfully' })
  @ApiResponse({ status: 404, description: 'File not found' })
  async getS3File(@Param('id') id: string) {
    return await this.fileService.getFile(id);
  }
  @Patch(':id')
  @ApiOperation({ summary: 'Update a file' })
  @ApiResponse({ status: 200, description: 'File updated successfully' })
  @ApiResponse({ status: 404, description: 'File not found' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        name: { type: 'string', example: 'updated-file.txt' },
        content: { type: 'string', example: 'Updated content here...' },
      },
    },
  })
  async updateFile(
    @Param('id') id: string,
    @Body() body: { name?: string; content?: string },
  ) {
    return await this.fileService.updateFile(id, body.name, body.content);
  }
  @Delete(':id')
  @ApiOperation({ summary: 'Delete a file' })
  @ApiResponse({ status: 200, description: 'File deleted successfully' })
  @ApiResponse({ status: 404, description: 'File not found' })
  async deleteFile(@Param('id') id: string) {
    return await this.fileService.deleteFile(id);
  }

  @Get('read')
  @ApiOperation({ summary: 'Read file content' })
  @ApiQuery({ name: 'path', required: true, description: 'Path to the file' })
  @ApiResponse({ status: 200, description: 'File read successfully' })
  async read(@Query('path') path: string) {
    return this.fileService.readFile(path);
  }

  @Delete('delete')
  @ApiOperation({ summary: 'Delete a file or folder' })
  @ApiQuery({
    name: 'path',
    required: true,
    description: 'Path to the file or folder',
  })
  @ApiResponse({
    status: 200,
    description: 'File or folder deleted successfully',
  })
  async delete(@Query('path') path: string) {
    return this.fileService.deleteFileOrFolder(path);
  }
}
