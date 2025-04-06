# FileService Documentation

## Overview
`FileService` is a NestJS service responsible for managing files and folders. It provides functionality to create, list, retrieve, update, and delete files and directories. It integrates with AWS S3 for cloud storage and Prisma for database interactions.

## Dependencies
- `@nestjs/common`: Provides core NestJS decorators and exceptions.
- `fs-extra`: Used for file system operations.
- `path`: Node.js module for handling file paths.
- `@aws-sdk/client-s3`: AWS SDK for managing S3 operations.
- `uuid`: Generates unique identifiers.
- `PrismaService`: Database service for handling file metadata.
- `dotenv`: Loads environment variables.
- `@nestjs/core`: Provides NestJS core functionalities.
- `express`: Used for handling requests.
- `stream`: Node.js module for working with streams.
- `UserDto`: Defines the user data transfer object.

## Environment Variables
Ensure the following environment variables are set:
```
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
S3_BUCKET_NAME=your-bucket-name
```

## Constructor
```typescript
constructor(
  @Inject('EXCLUDED_FOLDERS') private readonly EXCLUDED_FOLDERS: string[],
  private prisma: PrismaService,
  @Inject(REQUEST) private readonly request: Request & { user?: UserDto }
) {}
```

## Methods

### 1. `getFileTree`
Retrieves the directory tree structure.
```typescript
private getFileTree(dir: string, recursive: boolean = false): any[]
```
**Parameters:**
- `dir` (string): Directory path.
- `recursive` (boolean): Whether to fetch nested directories.

### 2. `createFolder`
Creates a new folder.
```typescript
async createFolder(name: string, createdById: string, parentId?: string)
```
**Parameters:**
- `name` (string): Folder name.
- `createdById` (string): User ID.
- `parentId` (string, optional): Parent folder ID.

### 3. `listFolders`
Lists all folders for a user.
```typescript
async listFolders(parentId?: string)
```
**Parameters:**
- `parentId` (string, optional): Parent folder ID.

### 4. `createFile`
Uploads a file to S3 and stores metadata in the database.
```typescript
async createFile(name: string, content: string, createdById: string, folderId?: string)
```
**Parameters:**
- `name` (string): File name.
- `content` (string): File content.
- `createdById` (string): User ID.
- `folderId` (string, optional): Folder ID.

### 5. `getFile`
Fetches a file from S3.
```typescript
async getFile(id: string)
```
**Parameters:**
- `id` (string): File ID.

### 6. `updateFile`
Updates a file in S3 and the database.
```typescript
async updateFile(id: string, newName?: string, newContent?: string)
```
**Parameters:**
- `id` (string): File ID.
- `newName` (string, optional): New file name.
- `newContent` (string, optional): New file content.

### 7. `deleteFile`
Deletes a file from S3 and the database.
```typescript
async deleteFile(id: string)
```
**Parameters:**
- `id` (string): File ID.

### 8. `getFilesByDirectory`
Retrieves files from a directory.
```typescript
async getFilesByDirectory(directory: string = '', recursive: boolean = false): Promise<any>
```
**Parameters:**
- `directory` (string): Directory path.
- `recursive` (boolean): Whether to include subdirectories.

### 9. `getFileContent`
Reads the content of a file.
```typescript
async getFileContent(filePath: string): Promise<any>
```
**Parameters:**
- `filePath` (string): Path to the file.

### 10. `createOrUpdateFile`
Creates or updates a file.
```typescript
async createOrUpdateFile(filePath: string, content?: string): Promise<{ path: string; message: string }>
```
**Parameters:**
- `filePath` (string): File path.
- `content` (string, optional): File content.

### 11. `readFile`
Reads file contents.
```typescript
async readFile(filePath: string): Promise<{ path: string; content: string }>
```
**Parameters:**
- `filePath` (string): File path.

## Error Handling
- `NotFoundException`: Thrown when a file or folder is not found.
- `BadRequestException`: Thrown for invalid operations (e.g., file already exists, S3 upload failure).
- `InternalServerErrorException`: Thrown for unexpected errors.

## Security Considerations
- Ensure proper IAM permissions for AWS S3.
- Validate user ownership before performing operations.
- Securely store and load environment variables.

## Future Enhancements
- Implement file versioning.
- Add support for multiple file types.
- Enable file sharing with permissions.


