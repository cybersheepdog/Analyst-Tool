import asyncio
from elasticsearch import Elasticsearch
from analyst_tool_utilities import color

class AsyncAnalystToolC2Live:
    def __init__(self, headers):
        self.es = Elasticsearch(headers.get('c2_live_url'))
        self.index = headers.get('c2_live_index')

    async def lookup(self, ip):
        query = {"query": {"match": {"ip": ip}}}
        
        try:
            # Use to_thread for blocking Elasticsearch calls
            response = await asyncio.to_thread(self.es.search, index=self.index, body=query)
            self._process_results(response)
        except Exception as e:
            print(f"[-] C2Live error querying {ip}: {e}")

    def _process_results(self, response):
        hits = response.get('hits', {}).get('hits', [])
        if not hits:
            print("\nC2 Live results:\n\tIP not found in tracked C2's.")
            return

        frameworks = sorted({hit['_source']['framework'] for hit in hits})
        
        print("\nC2 Live results:")
        for fw in frameworks:
            ts = sorted([hit['_source']['@timestamp'][0:10] for hit in hits if hit['_source']['framework'] == fw])
            print(f"\t{fw}\n\t\tFirst Seen: {ts[0]}\n\t\tLast Seen: {ts[-1]}")
