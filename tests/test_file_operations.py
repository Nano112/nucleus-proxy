"""
Comprehensive tests for file operations: rename, move, copy, and batch operations.
"""

import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch
from app.nucleus.client import NucleusClient
from app.routes.files import files_bp
from sanic import Sanic


# Unit tests for NucleusClient methods
class TestNucleusClientOperations:
    """Unit tests for rename2 and copy2 methods in NucleusClient."""
    
    @pytest.mark.asyncio
    async def test_rename2_single_success(self):
        """Test successful single rename operation."""
        client = NucleusClient("test-host")
        client.connection_token = "test-token"
        
        # Mock the API call
        with patch.object(client, 'call_api_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = {
                "status": "OK",
                "responses": ["OK"]
            }
            
            result = await client.rename2([{
                "src": {"path": "/test/file.txt"},
                "dst": {"path": "/test/renamed.txt"},
                "message": "Test rename"
            }])
            
            assert result['status'] == 'OK'
            assert result['succeeded'] == 1
            assert result['failed'] == 0
            assert result['results'][0]['success'] is True
            assert result['results'][0]['src'] == '/test/file.txt'
            assert result['results'][0]['dst'] == '/test/renamed.txt'
    
    @pytest.mark.asyncio
    async def test_rename2_batch_mixed_results(self):
        """Test batch rename with mixed success/failure results."""
        client = NucleusClient("test-host")
        client.connection_token = "test-token"
        
        with patch.object(client, 'call_api_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = {
                "status": "PartiallyCompleted",
                "responses": ["OK", "NotExist", "Denied", "AlreadyExists"]
            }
            
            paths = [
                {"src": {"path": "/file1.txt"}, "dst": {"path": "/new1.txt"}},
                {"src": {"path": "/file2.txt"}, "dst": {"path": "/new2.txt"}},
                {"src": {"path": "/file3.txt"}, "dst": {"path": "/new3.txt"}},
                {"src": {"path": "/file4.txt"}, "dst": {"path": "/new4.txt"}}
            ]
            
            result = await client.rename2(paths)
            
            assert result['status'] == 'PartiallyCompleted'
            assert result['succeeded'] == 1
            assert result['failed'] == 3
            assert result['results'][0]['success'] is True
            assert result['results'][1]['status'] == 'NotExist'
            assert result['results'][2]['status'] == 'Denied'
            assert result['results'][3]['status'] == 'AlreadyExists'
    
    @pytest.mark.asyncio
    async def test_move_file_convenience_method(self):
        """Test the move_file convenience method."""
        client = NucleusClient("test-host")
        client.connection_token = "test-token"
        
        with patch.object(client, 'rename2', new_callable=AsyncMock) as mock_rename2:
            mock_rename2.return_value = {
                "status": "OK",
                "results": [{
                    "src": "/old/path.txt",
                    "dst": "/new/path.txt",
                    "status": "OK",
                    "success": True
                }],
                "succeeded": 1,
                "failed": 0
            }
            
            result = await client.move_file("/old/path.txt", "/new/path.txt")
            
            assert result['status'] == 'OK'
            assert result['src'] == '/old/path.txt'
            assert result['dst'] == '/new/path.txt'
            assert result['error'] is None
    
    @pytest.mark.asyncio
    async def test_copy2_single_success(self):
        """Test successful single copy operation."""
        client = NucleusClient("test-host")
        client.connection_token = "test-token"
        
        with patch.object(client, 'call_api_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = {
                "status": "OK",
                "responses": ["OK"],
                "transaction_ids": [12345]
            }
            
            result = await client.copy2([{
                "src": {"path": "/source.txt"},
                "dst": {"path": "/copy.txt"},
                "message": "Test copy"
            }])
            
            assert result['status'] == 'OK'
            assert result['succeeded'] == 1
            assert result['failed'] == 0
            assert result['results'][0]['success'] is True
            assert result['results'][0]['transaction_id'] == 12345
    
    @pytest.mark.asyncio
    async def test_copy2_with_checkpoint(self):
        """Test copy operation with specific checkpoint version."""
        client = NucleusClient("test-host")
        client.connection_token = "test-token"
        
        with patch.object(client, 'call_api_method', new_callable=AsyncMock) as mock_call:
            mock_call.return_value = {
                "status": "OK",
                "responses": ["OK"],
                "transaction_ids": [67890]
            }
            
            result = await client.copy2([{
                "src": {"path": "/versioned.txt", "checkpoint": 42},
                "dst": {"path": "/restored.txt"},
                "message": "Restore from checkpoint"
            }])
            
            assert result['status'] == 'OK'
            assert result['results'][0]['checkpoint'] == 42
            assert result['results'][0]['transaction_id'] == 67890
    
    @pytest.mark.asyncio
    async def test_copy_file_convenience_method(self):
        """Test the copy_file convenience method."""
        client = NucleusClient("test-host")
        client.connection_token = "test-token"
        
        with patch.object(client, 'copy2', new_callable=AsyncMock) as mock_copy2:
            mock_copy2.return_value = {
                "status": "OK",
                "results": [{
                    "src": "/original.txt",
                    "dst": "/duplicate.txt",
                    "status": "OK",
                    "success": True,
                    "transaction_id": 99999
                }],
                "transaction_ids": [99999]
            }
            
            result = await client.copy_file("/original.txt", "/duplicate.txt")
            
            assert result['status'] == 'OK'
            assert result['transaction_id'] == 99999
            assert result['error'] is None


# Integration tests for API routes
@pytest.mark.asyncio
class TestFileOperationsRoutes:
    """Integration tests for file operation routes."""
    
    @pytest.fixture
    def app(self):
        """Create test app with files blueprint."""
        Sanic.test_mode = True
        app = Sanic("files-test-suite")
        app.blueprint(files_bp)
        try:
            yield app
        finally:
            Sanic._app_registry.clear()
            Sanic.test_mode = False
    
    @pytest.fixture
    def mock_auth(self):
        """Mock authentication decorator."""
        def decorator(f):
            return f
        return decorator
    
    @pytest.mark.asyncio
    async def test_rename_path_route(self, app, mock_auth):
        """Test the /rename endpoint."""
        with patch('app.routes.files.require_auth', mock_auth), \
             patch('app.routes.files.ensure_authenticated', new_callable=AsyncMock) as mock_ensure:
            
            mock_client = AsyncMock()
            mock_client.move_file.return_value = {
                "status": "OK",
                "src": "/old.txt",
                "dst": "/new.txt"
            }
            mock_ensure.return_value = mock_client
            
            request, response = await app.asgi_client.post(
                "/v1/files/rename",
                json={
                    "src": "/old.txt",
                    "dst": "/new.txt",
                    "message": "Test rename"
                }
            )
            
            assert response.status == 200
            data = json.loads(response.body)
            assert data['status'] == 'OK'
            assert 'Successfully moved' in data['message']
    
    @pytest.mark.asyncio
    async def test_rename_path_not_found(self, app, mock_auth):
        """Test rename endpoint with non-existent source."""
        with patch('app.routes.files.require_auth', mock_auth), \
             patch('app.routes.files.ensure_authenticated', new_callable=AsyncMock) as mock_ensure:
            
            mock_client = AsyncMock()
            mock_client.move_file.return_value = {
                "status": "NOT_EXIST",
                "error": "Path does not exist"
            }
            mock_ensure.return_value = mock_client
            
            request, response = await app.asgi_client.post(
                "/v1/files/rename",
                json={"src": "/missing.txt", "dst": "/new.txt"}
            )
            
            assert response.status == 404
            data = json.loads(response.body)
            assert 'not found' in data['error']
    
    @pytest.mark.asyncio
    async def test_batch_rename_route(self, app, mock_auth):
        """Test the /rename/batch endpoint."""
        with patch('app.routes.files.require_auth', mock_auth), \
             patch('app.routes.files.ensure_authenticated', new_callable=AsyncMock) as mock_ensure:
            
            mock_client = AsyncMock()
            mock_client.rename2.return_value = {
                "status": "OK",
                "results": [
                    {"src": "/a.txt", "dst": "/b.txt", "success": True},
                    {"src": "/c.txt", "dst": "/d.txt", "success": True}
                ],
                "succeeded": 2,
                "failed": 0
            }
            mock_ensure.return_value = mock_client
            
            request, response = await app.asgi_client.post(
                "/v1/files/rename/batch",
                json={
                    "paths_to_rename": [
                        {"src": {"path": "/a.txt"}, "dst": {"path": "/b.txt"}},
                        {"src": {"path": "/c.txt"}, "dst": {"path": "/d.txt"}}
                    ]
                }
            )
            
            assert response.status == 200
            data = json.loads(response.body)
            assert data['succeeded'] == 2
            assert data['failed'] == 0
    
    @pytest.mark.asyncio
    async def test_copy_path_route(self, app, mock_auth):
        """Test the /copy endpoint."""
        with patch('app.routes.files.require_auth', mock_auth), \
             patch('app.routes.files.ensure_authenticated', new_callable=AsyncMock) as mock_ensure:
            
            mock_client = AsyncMock()
            mock_client.copy_file.return_value = {
                "status": "OK",
                "src": "/original.txt",
                "dst": "/copy.txt",
                "transaction_id": 12345
            }
            mock_ensure.return_value = mock_client
            
            request, response = await app.asgi_client.post(
                "/v1/files/copy",
                json={
                    "src": "/original.txt",
                    "dst": "/copy.txt"
                }
            )
            
            assert response.status == 200
            data = json.loads(response.body)
            assert data['status'] == 'OK'
            assert data['transaction_id'] == 12345
            assert 'Successfully copied' in data['message']
    
    @pytest.mark.asyncio
    async def test_copy_with_checkpoint_route(self, app, mock_auth):
        """Test copy with checkpoint version."""
        with patch('app.routes.files.require_auth', mock_auth), \
             patch('app.routes.files.ensure_authenticated', new_callable=AsyncMock) as mock_ensure:
            
            mock_client = AsyncMock()
            mock_client.copy_file.return_value = {
                "status": "OK",
                "src": "/versioned.txt",
                "dst": "/restored.txt",
                "checkpoint": 100,
                "transaction_id": 54321
            }
            mock_ensure.return_value = mock_client
            
            request, response = await app.asgi_client.post(
                "/v1/files/copy",
                json={
                    "src": "/versioned.txt",
                    "dst": "/restored.txt",
                    "checkpoint": 100
                }
            )
            
            assert response.status == 200
            data = json.loads(response.body)
            assert data['checkpoint'] == 100
    
    @pytest.mark.asyncio
    async def test_batch_copy_route(self, app, mock_auth):
        """Test the /copy/batch endpoint."""
        with patch('app.routes.files.require_auth', mock_auth), \
             patch('app.routes.files.ensure_authenticated', new_callable=AsyncMock) as mock_ensure:
            
            mock_client = AsyncMock()
            mock_client.copy2.return_value = {
                "status": "OK",
                "results": [
                    {"src": "/a.txt", "dst": "/a_copy.txt", "success": True},
                    {"src": "/b.txt", "dst": "/b_copy.txt", "success": True}
                ],
                "succeeded": 2,
                "failed": 0,
                "transaction_ids": [111, 222]
            }
            mock_ensure.return_value = mock_client
            
            request, response = await app.asgi_client.post(
                "/v1/files/copy/batch",
                json={
                    "paths_to_copy": [
                        {"src": {"path": "/a.txt"}, "dst": {"path": "/a_copy.txt"}},
                        {"src": {"path": "/b.txt"}, "dst": {"path": "/b_copy.txt"}}
                    ]
                }
            )
            
            assert response.status == 200
            data = json.loads(response.body)
            assert data['succeeded'] == 2
            assert len(data['transaction_ids']) == 2

    @pytest.mark.asyncio
    async def test_create_directory_tree_success(self, app, mock_auth):
        """Test creating a nested directory tree."""
        structure = {
            "docs": {
                "design": {"drafts": {}},
                "specs": {}
            },
            "src": {
                "services": {"api": {}},
                "assets": {
                    "images": {},
                    "fonts": {}
                }
            }
        }

        expected_paths = [
            "/projects/demo",
            "/projects/demo/docs",
            "/projects/demo/docs/design",
            "/projects/demo/docs/design/drafts",
            "/projects/demo/docs/specs",
            "/projects/demo/src",
            "/projects/demo/src/services",
            "/projects/demo/src/services/api",
            "/projects/demo/src/assets",
            "/projects/demo/src/assets/images",
            "/projects/demo/src/assets/fonts",
        ]

        with patch('app.routes.files.require_auth', mock_auth), \
             patch('app.routes.files.ensure_authenticated', new_callable=AsyncMock) as mock_ensure, \
             patch('app.routes.files.ensure_paths_permission', return_value=None) as mock_perm:

            mock_client = AsyncMock()

            async def side_effect(path):
                if path == "/projects/demo":
                    return {"status": "ALREADY_EXISTS"}
                return {"status": "OK"}

            mock_client.create_folder.side_effect = side_effect
            mock_ensure.return_value = mock_client

            request, response = await app.asgi_client.post(
                "/v1/files/mkdir/tree",
                json={
                    "base_path": "/projects/demo",
                    "structure": structure,
                }
            )

            assert response.status == 200
            data = json.loads(response.body)
            assert data['existing'] == 1
            assert data['created'] == len(expected_paths) - 1
            assert data['failed'] == []
            mock_perm.assert_called_once()

            called_paths = [call.args[0] for call in mock_client.create_folder.call_args_list]
            assert called_paths == expected_paths

    @pytest.mark.asyncio
    async def test_create_directory_tree_partial_failure(self, app, mock_auth):
        """Failures should be reported with multi-status."""
        structure = {
            "src": {
                "components": {},
                "services": {"api": {}}
            }
        }

        with patch('app.routes.files.require_auth', mock_auth), \
             patch('app.routes.files.ensure_authenticated', new_callable=AsyncMock) as mock_ensure, \
             patch('app.routes.files.ensure_paths_permission', return_value=None):

            mock_client = AsyncMock()

            async def side_effect(path):
                if path.endswith('/services/api'):
                    return {"status": "DENIED", "error": "No permission"}
                return {"status": "OK"}

            mock_client.create_folder.side_effect = side_effect
            mock_ensure.return_value = mock_client

            request, response = await app.asgi_client.post(
                "/v1/files/mkdir/tree",
                json={
                    "base_path": "/projects/sample",
                    "structure": structure,
                }
            )

            assert response.status == 207
            data = json.loads(response.body)
            assert len(data['failed']) == 1
            assert data['failed'][0]['path'].endswith('/services/api')

    @pytest.mark.asyncio
    async def test_create_directory_tree_invalid_payload(self, app, mock_auth):
        """Invalid payloads must return 400."""
        with patch('app.routes.files.require_auth', mock_auth):
            request, response = await app.asgi_client.post(
                "/v1/files/mkdir/tree",
                json={
                    "base_path": "/projects/invalid",
                    "structure": [],
                }
            )

            assert response.status == 400
            data = json.loads(response.body)
            assert 'structure must be a non-empty object' in data['error']


# Real integration tests with Nucleus server
@pytest.mark.integration
class TestFileOperationsIntegration:
    """Integration tests with real Nucleus server."""
    
    @pytest.mark.asyncio
    async def test_rename_move_copy_flow(self):
        """Test complete rename, move, and copy flow with real server."""
        import os
        import tempfile
        from app.nucleus.client import ensure_authenticated
        
        # Skip if no Nucleus host configured
        if not os.getenv('NUCLEUS_HOST'):
            pytest.skip("NUCLEUS_HOST not configured")
        
        client = await ensure_authenticated()
        
        # Create a test directory
        test_dir = f"/Users/test_{os.getpid()}/"
        result = await client.create_directory(test_dir)
        assert result.get('status') in ['OK', 'DONE', 'AlreadyExists']
        
        try:
            # Upload a test file
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write("Test content for file operations")
                temp_path = f.name
            
            original_path = f"{test_dir}original.txt"
            upload_result = await client.upload_file_single_shot(
                temp_path, test_dir, "original.txt"
            )
            assert upload_result.get('status') == 'OK' or upload_result.get('response')
            
            # Test rename (within same directory)
            renamed_path = f"{test_dir}renamed.txt"
            rename_result = await client.move_file(original_path, renamed_path)
            assert rename_result.get('status') == 'OK'
            
            # Verify rename worked
            stat_result = await client.get_file_info(renamed_path)
            assert stat_result.get('status') == 'OK'
            assert stat_result.get('type') == 'File'
            
            # Test move (to different directory)
            move_dir = f"{test_dir}subdir/"
            await client.create_directory(move_dir)
            moved_path = f"{move_dir}moved.txt"
            move_result = await client.move_file(renamed_path, moved_path)
            assert move_result.get('status') == 'OK'
            
            # Test copy
            copied_path = f"{test_dir}copied.txt"
            copy_result = await client.copy_file(moved_path, copied_path)
            assert copy_result.get('status') == 'OK'
            
            # Verify both files exist
            moved_stat = await client.get_file_info(moved_path)
            copied_stat = await client.get_file_info(copied_path)
            assert moved_stat.get('status') == 'OK'
            assert copied_stat.get('status') == 'OK'
            
            # Test batch rename
            batch_rename_result = await client.rename2([
                {"src": {"path": moved_path}, "dst": {"path": f"{test_dir}batch1.txt"}},
                {"src": {"path": copied_path}, "dst": {"path": f"{test_dir}batch2.txt"}}
            ])
            assert batch_rename_result['succeeded'] >= 1
            
            # Clean up
            await client.delete_paths_batch([
                f"{test_dir}batch1.txt",
                f"{test_dir}batch2.txt"
            ])
            await client.delete_path(move_dir)
            await client.delete_path(test_dir)
            
        finally:
            # Clean up temp file
            try:
                os.unlink(temp_path)
            except:
                pass
    
    @pytest.mark.asyncio
    async def test_copy_with_checkpoint_integration(self):
        """Test copying a specific version of a file."""
        import os
        from app.nucleus.client import ensure_authenticated
        
        # Skip if no Nucleus host configured
        if not os.getenv('NUCLEUS_HOST'):
            pytest.skip("NUCLEUS_HOST not configured")
        
        # This test would require a Nucleus server with versioning enabled
        # and ability to retrieve checkpoints - skipping for now as it's
        # an advanced feature that may not be available in all deployments
        pytest.skip("Checkpoint-based copy requires versioning-enabled Nucleus server")
