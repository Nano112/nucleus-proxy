import asyncio,json
from collections import deque
from app.nucleus.client import NucleusClient

class Socket:
    def __init__(self):self.frames=deque();self.receiving=False
    async def send(self,message):
        p=json.loads(message);i=p['id']
        self.frames.append({'id':i-1,'status':'DONE'})
        self.frames.append({'id':i-1,'status':'OK','uri_redirection':'https://nucleus.example/wrong'})
        if p['command']=='stat2':
            self.frames.append({'id':i,'status':'OK','type':'asset','uri':p['path']['path'],'size':42})
        else:
            self.frames.append({'id':i,'status':'OK','uri_redirection':'https://nucleus.example'+p['uri']})
        self.frames.append({'id':i,'status':'DONE'})
    async def recv(self):
        assert not self.receiving,'Concurrent recv would corrupt request ownership'
        self.receiving=True
        await asyncio.sleep(0)
        result=json.dumps(self.frames.popleft())
        self.receiving=False
        return result


def test_concurrent_metadata_and_downloads_ignore_old_frames():
    async def run():
        c=NucleusClient();c.api_websocket=Socket();c.connection_token='test'
        c.decode_response=json.loads;c._rewrite_download_url=lambda url:url
        results=await asyncio.gather(*[fn for i in range(10) for fn in (c.get_file_info('/asset'+str(i)),c.get_download_url('/asset'+str(i)))])
        for i in range(10):
            assert results[i*2]['uri']=='/asset'+str(i)
            assert results[i*2+1]['download_url']=='https://nucleus.example/asset'+str(i)
    asyncio.run(run())
