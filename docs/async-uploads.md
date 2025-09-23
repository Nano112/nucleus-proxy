# Async Upload Behavior

## Overview

The Nucleus Proxy now supports asynchronous upload handling, allowing users to continue working while large files sync to Nucleus in the background. This significantly improves the user experience, especially for large file uploads.

## Behavior by File Size

### Small Files (< 10 MB)
- **Full synchronous upload**: The upload waits for complete sync to Nucleus
- **User experience**: Progress bar shows both upload and sync progress
- **Completion**: User sees "uploaded successfully" only after sync completes
- **Typical duration**: 1-5 seconds for most small files

### Large Files (>= 10 MB) 
- **Asynchronous sync**: Upload completes to proxy, then syncs in background
- **User experience**: 
  - File appears in file list immediately after proxy upload
  - Message: "File uploaded. Syncing in background..."
  - User can navigate away or close the page
  - Background sync continues on the server
- **Sync tracking**: Background process tracks sync status for up to 2 minutes
- **Success notification**: If user stays on page, they see "File synced successfully" when complete

## Technical Implementation

### Client-Side Changes

1. **Upload Function Enhancement**
   ```javascript
   client.uploadFile({
     file: file,
     path: currentPath,
     onProgress: updateProgress,
     skipSyncWait: file.size >= 10 * 1024 * 1024  // Skip for files >= 10MB
   })
   ```

2. **Background Sync Tracking**
   - Polls `/v1/uploads/status` endpoint every second
   - Maximum tracking duration: 2 minutes
   - Handles session cleanup gracefully (404 responses)

3. **Error Handling**
   - Session not found (404): Assumes successful completion
   - Sync failures: Shows error notification to user
   - Network errors: Silently stops tracking

### Server-Side Behavior

1. **Upload Session Lifecycle**
   - Session created during upload initiation
   - Parts uploaded and tracked
   - Commit triggered (assembles parts and syncs to Nucleus)
   - Session cleaned up after successful sync

2. **Status Responses**
   - `pending`: Upload in progress
   - `assembling`: Parts being assembled
   - `committing`: Syncing to Nucleus
   - `completed`: Successfully synced
   - `failed`: Sync failed

## Benefits

1. **Improved User Experience**
   - No waiting for large file syncs
   - Can continue working immediately
   - Visual feedback for sync progress

2. **Better Resource Utilization**
   - Browser connection not held open during long syncs
   - Server handles sync independently
   - Reduced timeout issues

3. **Reliability**
   - Sync continues even if user closes page
   - Graceful handling of session cleanup
   - Clear error messaging

## Configuration

The 10MB threshold for async behavior can be adjusted in `index.html`:

```javascript
const skipSync = file.size > 10 * 1024 * 1024; // Adjust threshold here
```

## Error Scenarios

### Upload Session Not Found
- **Cause**: Session cleaned up after successful sync
- **Handling**: Treated as successful completion
- **User Impact**: None (transparent)

### Sync Failure
- **Cause**: Nucleus server issues, network problems
- **Handling**: Error notification shown
- **User Impact**: File may need re-upload

### Timeout
- **Cause**: Very large files taking > 2 minutes to sync
- **Handling**: Tracking stops, sync continues on server
- **User Impact**: No final notification, but file will appear

## Best Practices

1. **File Size Considerations**
   - Keep individual files under 1GB when possible
   - Use compression for large datasets
   - Consider splitting very large files

2. **Network Stability**
   - Ensure stable connection for initial upload
   - Background sync is resilient to brief interruptions
   - Monitor server logs for sync failures

3. **User Communication**
   - Clear messaging about sync status
   - Educate users about background sync behavior
   - Provide guidance on file size limits

## Testing

Run the async upload test suite:

```bash
export NUCLEUS_HOST=your-server
uv run python test_upload_async.py
```

This tests:
- Small file synchronous upload
- Large file asynchronous upload
- Multiple file uploads
- Session cleanup handling