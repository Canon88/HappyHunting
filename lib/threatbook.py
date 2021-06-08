'''
Author: Canon
Date: 2020-11-08 14:09:37
LastEditTime: 2021-06-09 00:23:14
'''

import aiohttp
import asyncio


class ThreatBook():
    """
    Threat intelligence: Threat Book
    https://x.threatbook.cn/nodev4/vb4/API
    """

    def __init__(self, key):
        self.key = key
        self.ua = "HappyHunting"
        self.urls = {
            'compromise': 'https://api.threatbook.cn/v3/scene/dns',
            'reputation': 'https://api.threatbook.cn/v3/scene/ip_reputation'
        }

    async def _request(self, session, url, params={}):
        '''
        @Description: Request Threatbook API
        @Date: 2021-06-06 09:11:24
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
            await self._parser(r)

    async def _parser(self, r):
        '''
        @Description: Parse API results
        @Date: 2021-06-06 09:17:13
        @param {dict} r
        @return {*}
        '''
        if self.parser_module == 'reputation':
            results = r['data']
            await self.parser_indicators(results)
        elif self.parser_module == 'compromise':
            results = list(r['data'].values())[0]
            await self.parser_indicators(results)
        else:
            print("I didn't do anything!")

    async def get_indicators(self, data):
        '''
        @Description: Get threat intelligence
        @Date: 2021-06-06 08:34:18
        @param {list} data
        @param {str} type: reputation、compromise
        @return {list}
        '''

        url = self.urls[self.parser_module]
        async with aiohttp.ClientSession() as session:
            task_list = []
            for ioc in data:
                params = {'apikey': self.key, 'resource': ioc}
                req = self._request(session, url, params)
                task = asyncio.create_task(req)
                task_list.append(task)
            await asyncio.gather(*task_list, return_exceptions=True)
            return self.results

    async def parser_indicators(self, results):
        '''
        @Description: Parse threat intelligence results
        @Date: 2021-06-06 08:39:19
        @param {dict} results
        @return {list}
        '''
        
        for k, v in results.items():
            intel = {
                'ioc': k,
                'malicious': v['is_malicious'],
                'confidence': v['confidence_level'],
                'tags': v['judgments']
            }
            self.results.append(intel)

    async def main(self, data, type):
        self.parser_module = type
        if self.parser_module in ['reputation', 'compromise']:
            return await self.get_indicators(data)
        else:
            pass
