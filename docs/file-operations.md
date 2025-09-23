# File Operations API Documentation

## Overview

The Nucleus Proxy now supports comprehensive file operations including rename, move, copy, and batch operations. These features are implemented with proper error handling, detailed status reporting, and support for version control (checkpoints).

## Features Implemented

### 1. Rename/Move Operations

- **Single file rename/move**: Move or rename a file/folder with a single API call
- **Batch rename/move**: Perform multiple rename operations in a single atomic request
- **Cross-directory moves**: Move files between different directories
- **Commit messages**: Optional commit messages for version control integration

### 2. Copy Operations  

- **Single file copy**: Copy a file/folder to a new location
- **Batch copy**: Copy multiple files in a single request
- **Version-aware copying**: Copy specific versions of files using checkpoint numbers
- **Transaction tracking**: Each copy operation returns a transaction ID for auditing

### 3. Error Handling

All operations include comprehensive error handling with appropriate HTTP status codes:
- `200 OK`: Success
- `400 Bad Request`: Invalid parameters
- `403 Forbidden`: Permission denied
- `404 Not Found`: Source path doesn't exist
- `409 Conflict`: Destination already exists
- `500 Internal Server Error`: Server-side failures

## API Endpoints

### Single File Rename/Move

```http
POST /v1/files/rename
Authorization: Bearer <token>
Content-Type: application/json

{
  "src": "/path/to/source.txt",
  "dst": "/path/to/destination.txt",
  "message": "Optional commit message"
}
```

**Response:**
```json
{
  "status": "OK",
  "src": "/path/to/source.txt",
  "dst": "/path/to/destination.txt",
  "message": "Successfully moved /path/to/source.txt to /path/to/destination.txt"
}
```

### Batch Rename/Move

```http
POST /v1/files/rename/batch
Authorization: Bearer <token>
Content-Type: application/json

{
  "paths_to_rename": [
    {
      "src": {"path": "/file1.txt"},
      "dst": {"path": "/renamed1.txt"},
      "message": "Rename file 1"
    },
    {
      "src": {"path": "/file2.txt"},
      "dst": {"path": "/moved/file2.txt"}
    }
  ]
}
```

**Response:**
```json
{
  "status": "OK",
  "results": [
    {
      "src": "/file1.txt",
      "dst": "/renamed1.txt",
      "status": "OK",
      "success": true
    },
    {
      "src": "/file2.txt",
      "dst": "/moved/file2.txt",
      "status": "OK",
      "success": true
    }
  ],
  "total": 2,
  "succeeded": 2,
  "failed": 0
}
```

### Single File Copy

```http
POST /v1/files/copy
Authorization: Bearer <token>
Content-Type: application/json

{
  "src": "/path/to/original.txt",
  "dst": "/path/to/copy.txt",
  "checkpoint": 12345,  // Optional: copy specific version
  "message": "Creating backup"
}
```

**Response:**
```json
{
  "status": "OK",
  "src": "/path/to/original.txt",
  "dst": "/path/to/copy.txt",
  "message": "Successfully copied /path/to/original.txt to /path/to/copy.txt",
  "transaction_id": 67890,
  "checkpoint": 12345  // If checkpoint was specified
}
```

### Batch Copy

```http
POST /v1/files/copy/batch
Authorization: Bearer <token>
Content-Type: application/json

{
  "paths_to_copy": [
    {
      "src": {"path": "/file1.txt"},
      "dst": {"path": "/backup/file1.txt"},
      "message": "Backup file 1"
    },
    {
      "src": {"path": "/file2.txt", "checkpoint": 100},
      "dst": {"path": "/restored/file2_v100.txt"},
      "message": "Restore from checkpoint 100"
    }
  ]
}
```

**Response:**
```json
{
  "status": "OK",
  "results": [
    {
      "src": "/file1.txt",
      "dst": "/backup/file1.txt",
      "status": "OK",
      "success": true,
      "transaction_id": 111
    },
    {
      "src": "/file2.txt",
      "dst": "/restored/file2_v100.txt",
      "checkpoint": 100,
      "status": "OK",
      "success": true,
      "transaction_id": 222
    }
  ],
  "total": 2,
  "succeeded": 2,
  "failed": 0,
  "transaction_ids": [111, 222]
}
```

## Client Methods

### NucleusClient Methods

The `NucleusClient` class provides both low-level batch methods and convenience methods:

#### Low-level Batch Methods
- `rename2(paths_to_rename)`: Batch rename/move operation
- `copy2(paths_to_copy)`: Batch copy operation with checkpoint support

#### Convenience Methods
- `move_file(source, destination, message)`: Simple single file move
- `copy_file(source, destination, checkpoint, message)`: Simple single file copy

### Example Usage

```python
from app.nucleus.client import ensure_authenticated

# Get authenticated client
client = await ensure_authenticated()

# Simple rename
result = await client.move_file("/old.txt", "/new.txt", "Renamed for clarity")

# Copy with checkpoint
result = await client.copy_file("/data.txt", "/backup.txt", checkpoint=42)

# Batch operations
batch_result = await client.rename2([
    {"src": {"path": "/a.txt"}, "dst": {"path": "/b.txt"}},
    {"src": {"path": "/c.txt"}, "dst": {"path": "/d.txt"}}
])
```

## Frontend Demo

A comprehensive frontend demo is available at `/static/file-operations-demo.html`. Features include:

- **Visual UI**: Clean, modern interface for all file operations
- **Authentication**: Bearer token input for API authentication
- **Single Operations**: Forms for individual rename/move and copy operations
- **Batch Operations**: Dynamic forms for batch rename and copy
- **Real-time Results**: Live feedback showing operation results
- **Error Display**: Clear error messages for failed operations

Access the demo at: `http://localhost:8088/static/file-operations-demo.html`

## Testing

Comprehensive test coverage is provided:

### Unit Tests
- `tests/test_file_operations.py::TestNucleusClientOperations`
  - Tests for rename2 and copy2 methods
  - Tests for convenience methods (move_file, copy_file)
  - Mixed success/failure batch operation tests

### Integration Tests  
- `tests/test_file_operations.py::TestFileOperationsRoutes`
  - API endpoint tests with mocked clients
  - Error handling validation
  
### Manual Integration Test
- `test_file_operations_manual.py`
  - End-to-end test against real Nucleus server
  - Tests complete workflow: upload, rename, move, copy, batch operations
  - Includes cleanup and error handling tests

Run tests with:
```bash
# Unit tests only
uv run pytest tests/test_file_operations.py::TestNucleusClientOperations -v

# All file operation tests
uv run pytest tests/test_file_operations.py -v

# Manual integration test (requires NUCLEUS_HOST env var)
export NUCLEUS_HOST=your-nucleus-server
uv run python test_file_operations_manual.py
```

## Implementation Details

### Protocol Compatibility
- Uses Nucleus `rename2` command for move/rename operations
- Uses Nucleus `copy2` command for copy operations
- Both commands support batch operations for efficiency
- Proper handling of the batch response format with per-item statuses

### Error Status Mapping
The implementation correctly maps Nucleus status codes to HTTP responses:
- `NotExist` → 404 Not Found
- `Denied` → 403 Forbidden
- `AlreadyExists` → 409 Conflict
- `FolderNotEmpty` → 400 Bad Request
- `InvalidParameters` → 400 Bad Request

### Batch Operation Handling
- Batch operations return detailed per-item results
- Overall status indicates if all operations succeeded or if there were partial failures
- Individual success/failure status for each item in the batch
- Count of succeeded vs failed operations

## Future Enhancements

Potential improvements for future iterations:

1. **Progress Tracking**: For large batch operations, implement progress callbacks
2. **Recursive Operations**: Add support for recursive directory operations
3. **Conflict Resolution**: Add options for handling existing files (overwrite, skip, rename)
4. **Undo Support**: Implement operation history and undo functionality
5. **Permissions Preservation**: Ensure file permissions are preserved during operations
6. **Metadata Preservation**: Preserve custom metadata and tags during copy operations
7. **WebSocket Support**: Real-time progress updates for long-running operations
8. **Queued Operations**: Queue system for batch operations to prevent timeouts

## Troubleshooting

### Common Issues

1. **"Path does not exist" errors**
   - Verify the source path exists using `/v1/files/stat`
   - Check for typos in the path
   - Ensure proper permissions

2. **"Destination already exists" errors**
   - Check if destination path is already in use
   - Consider using a different destination or deleting existing file first

3. **Timeout errors on large batches**
   - Split large batch operations into smaller chunks
   - Consider implementing async/queue-based processing

4. **Permission denied errors**
   - Verify authentication token is valid
   - Check user permissions for both source and destination paths
   - Ensure destination directory exists and is writable