'''
Author: Canon
Date: 2020-11-11 23:23:30
LastEditTime: 2021-06-09 01:29:40
'''

import aiohttp
import asyncio


class Shodan():
    """
    Threat intelligence: Shodan
    https://developer.shodan.io/api
    """

    def __init__(self, key):
        self.ua = "HappyHunting"
        self.urls = {
            'host': 'https://api.shodan.io/shodan/host/{}'
        }
        self.proxy = 'http://canon.loveyou.com'
        self.proxy_auth = aiohttp.BasicAuth(
            'canon', 'loveyou')
        self.q = asyncio.Queue()
        [self.q.put_nowait(k) for k in key]

    async def _request(self, session, url):
        self.results = []
        key = await self.q.get()
        params = {'key': key}
        await self.q.put(key)
        headers = {'User-Agent': self.ua}
        async with session.get(url, headers=headers, params=params, proxy=self.proxy, proxy_auth=self.proxy_auth) as resp:
            assert resp.status == 200
            r = await resp.json()
            await self._parser(r)

    async def _parser(self, r):
        if self.parser_module == 'host':
            await self.parser_hostinfo(r)
        else:
            print("I didn't do anything!")

    async def get_hostinfo(self, data):
        async with aiohttp.ClientSession() as session:
            task_list = []
            for ioc in data:
                url = self.urls[self.parser_module].format(ioc)
                req = self._request(session, url)
                task = asyncio.create_task(req)
                task_list.append(task)
            await asyncio.gather(*task_list, return_exceptions=True)
            return self.results

    async def parser_hostinfo(self, r):
        if r.get('ip_str'):
            results = {
                'ioc': r['ip_str'],
                'ports': [],
                'services': [],
                'vulns': r.get('vulns', []),
                'details': {'tcp': [], 'udp': []}
            }
            for i in r['data']:
                port = i['port']
                module = i['_shodan']['module']
                version = i.get('version', 'unknown')
                detail = {module: port, 'version': version}

                results['ports'].append(port)
                results['services'].append(module)
                results['details'][i['transport']].append(detail)
            self.results.append(results)

    async def _check(self, key):
        async with aiohttp.ClientSession() as session:
            url = 'https://api.shodan.io/api-info?key={}'.format(key)
            async with session.get(url) as resp:
                if resp.status == 401:
                    print(key)

    async def main(self, data, type):
        self.parser_module = type
        if self.parser_module == 'host':
            return await self.get_hostinfo(data)
        else:
            pass