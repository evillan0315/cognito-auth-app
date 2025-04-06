# FileController Documentation

## Overview
The `FileController` in this NestJS application provides API endpoints for file and folder management, including CRUD operations, retrieval of file content, and listing of directories. The controller is secured with AWS Cognito authentication.

## Authentication
- All routes are protected with `CognitoAuthGuard`.
- JWT authentication is required (`@ApiBearerAuth`).

## API Endpoints

### Create a Folder
**Endpoint:** `POST /file/folder`
- **Description:** Creates a new folder.
- **Request Body:**
  ```json
  {
    "name": "My New Folder",
    "createdById": "user-12345",
    "parentId": "folder-67890"
  }
  ```
- **Response:**
  - `201`: Folder created successfully.
  - `400`: Invalid request.

---

### List Folders
**Endpoint:** `GET /file/folder`
- **Description:** Retrieves a list of folders.
- **Query Parameters:**
  - `parentId` (optional): Parent folder ID.
- **Response:**
  - `200`: List of folders.

---

### Get Raw File
**Endpoint:** `GET /file/raw/:filePath`
- **Description:** Streams a file.
- **Response:**
  - `200`: File streamed.
  - `404`: File not found.
  - `500`: Error reading file.

---

### List Files in Directory
**Endpoint:** `GET /file/list`
- **Query Parameters:**
  - `directory` (optional): Path to the directory.
  - `recursive` (optional, boolean): Whether to list files recursively.
- **Response:**
  - `200`: List of files and directories.

---

### Get File Content
**Endpoint:** `GET /file/content`
- **Query Parameters:**
  - `filePath` (required): Path to the file.
- **Response:**
  - `200`: File content retrieved successfully.
  - `404`: File not found.

---

### Create a File
**Endpoint:** `POST /file/create`
- **Request Body:**
  ```json
  {
    "name": "document.txt",
    "content": "Hello, world!",
    "parentId": "folder-67890"
  }
  ```
- **Response:**
  - `201`: File created successfully.
  - `400`: Invalid request.

---

### Retrieve a File by ID
**Endpoint:** `GET /file/:id`
- **Response:**
  - `200`: File retrieved successfully.
  - `404`: File not found.

---

### Update a File
**Endpoint:** `PATCH /file/:id`
- **Request Body:**
  ```json
  {
    "name": "updated-file.txt",
    "content": "Updated content here..."
  }
  ```
- **Response:**
  - `200`: File updated successfully.
  - `404`: File not found.

---

### Delete a File
**Endpoint:** `DELETE /file/:id`
- **Response:**
  - `200`: File deleted successfully.
  - `404`: File not found.

---

### Read File Content
**Endpoint:** `GET /file/read`
- **Query Parameters:**
  - `path` (required): Path to the file.
- **Response:**
  - `200`: File read successfully.
  - `404`: File not found.

---

### Delete a File or Folder
**Endpoint:** `DELETE /file/delete`
- **Query Parameters:**
  - `path` (required): Path to the file or folder.
- **Response:**
  - `200`: File or folder deleted successfully.
  - `404`: File or folder not found.

## Error Handling
- `404`: Returned when a file or folder is not found.
- `400`: Returned for invalid requests.
- `500`: Returned for internal server errors.

## Security
- All routes require authentication.
- Uses AWS Cognito for securing endpoints.

## Dependencies
- `fs`, `path`, and `mime-types` are used for file operations.
- `@nestjs/swagger` is used for API documentation.
- `CognitoAuthGuard` is used for authentication.


