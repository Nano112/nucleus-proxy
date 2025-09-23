#!/usr/bin/env python3
import asyncio
from app.nucleus.client import NucleusClient
from app.config import settings

async def test():
    client = NucleusClient(settings.nucleus_host)
    await client.authenticate(settings.nucleus_username, settings.nucleus_password)
    await client.authorize_api_connection()
    
    # Test deleting a non-existent file
    result = await client.delete_path('/Users/omniverse/nonexistent.txt')
    print("Direct client result:", result)
    
    await client.close()

asyncio.run(test())