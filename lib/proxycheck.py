'''
Author: Canon
Date: 2020-11-14 23:23:30
LastEditTime: 2021-06-09 00:22:33
'''

import aiohttp
import asyncio


class ProxyCheck():
    """
    Threat intelligence: ProxyCheck
    http://proxycheck.io/v2/
    """

    def __init__(self, key):
        self.key = key
        self.ua = "HappyHunting"
        self.urls = {
            'proxy': 'http://proxycheck.io/v2/{}'
        }

    async def _request(self, session, url, params={}):
        '''
        @Description: Request ProxyCheck API
        @Date: 2021-06-05 18:57:26
        @param {object} session
        @param {str} url
        @param {dict} params
        @return {*}
        '''

        self.results = []
        headers = {'User-Agent': self.ua}
        async with session.get(url, params=params, headers=headers) as resp:
            assert resp.status == 200
            r = await resp.json()
            self.ioc = url.split('/')[-1]
            await self._parser(r)

    async def _parser(self, r):
        '''
        @Description: Parse API results
        @Date: 2021-06-06 09:17:13
        @param {dict} r
        @return {*}
        '''

        if self.parser_module == 'proxy':
            await self.parser_proxy(r)
        else:
            print("I didn't do anything!")

    async def check_proxy(self, data):
        '''
        @Description: Check IP is Proxy
        @Date: 2021-06-06 08:34:18
        @param {list} data
        @param {str} type: reputation、compromise
        @return {list}
        '''

        params = {
            'vpn': 1, 'asn': 1, 'time': 1, 'info': 0, 'risk': 1, 'port': 1,
            'seen': 1, 'days': 7, 'tag': 'siem', 'key': self.key
        }
        async with aiohttp.ClientSession() as session:
            task_list = []
            for ioc in data:
                url = self.urls[self.parser_module].format(ioc)
                req = self._request(session, url, params)
                task = asyncio.create_task(req)
                task_list.append(task)
            await asyncio.gather(*task_list, return_exceptions=True)
            return self.results

    async def parser_proxy(self, r):
        '''
        @Description: Parse Check Proxy results
        @Date: 2021-06-06 08:39:19
        @param {dict} results
        @return {list}
        '''
        
        ioc = self.ioc
        if r['status'] == 'ok':
            results = {
                'ioc': ioc,
                'country': r[ioc]['country'],
                'city': r[ioc]['proxy'],
                'proxy': r[ioc]['proxy'],
                'type': r[ioc]['type'],
                'provider': r[ioc]['provider']
            }
            self.results.append(results)

    async def main(self, data, type):
        self.parser_module = type
        if self.parser_module == 'proxy':
            return await self.check_proxy(data)
        else:
            pass