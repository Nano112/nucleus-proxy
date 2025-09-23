# Changelog

## [0.2.0] - File Operations Enhancement

### Added

#### Core Functionality
- **Rename/Move Operations**: Full support for renaming and moving files/folders
  - Single file rename with `POST /v1/files/rename`
  - Batch rename with `POST /v1/files/rename/batch`
  - Cross-directory moves supported
  - Optional commit messages for version control

- **Copy Operations**: Comprehensive file/folder copying capabilities
  - Single file copy with `POST /v1/files/copy`
  - Batch copy with `POST /v1/files/copy/batch`
  - Version-aware copying with checkpoint support
  - Transaction ID tracking for audit trails

- **NucleusClient Methods**:
  - `rename2()`: Batch rename/move with detailed per-item results
  - `copy2()`: Batch copy with checkpoint support
  - `move_file()`: Convenience method for single file moves
  - `copy_file()`: Convenience method for single file copies

#### User Interface
- **File Explorer Enhancements**:
  - Added Rename button for selected files/folders
  - Added Copy button with smart naming suggestions
  - Improved selection state management
  - Visual feedback for all operations

- **JavaScript Client Updates**:
  - Added `rename()` method for single operations
  - Added `renameBatch()` for batch operations
  - Added `copy()` method with checkpoint support
  - Added `copyBatch()` for batch operations

#### Documentation
- Comprehensive API documentation in README.md
- Detailed examples for all new endpoints
- curl command examples for testing
- Migration notes from legacy methods

### Changed
- Updated README.md with complete file operations documentation
- Enhanced error handling with specific HTTP status codes:
  - 404 for non-existent paths
  - 403 for permission denied
  - 409 for conflicts (already exists)
  - 400 for invalid parameters

### Testing
- Added comprehensive unit tests for all new client methods
- Integration tests for REST API endpoints
- Manual test script for real server validation
- All tests passing with good coverage

## [0.1.0] - Initial Release

### Features
- Basic file operations (list, create, delete)
- Authentication and authorization
- Upload and download functionality
- Multi-tenancy support
- Real-time events via WebSocket/SSE
- Monitoring and health checks
- OpenAPI documentation