'''
Author: Canon
Date: 2020-11-07 19:05:22
LastEditTime: 2021-06-09 00:21:23
'''

import aiohttp
import asyncio


class HIBP():
    """
    Threat intelligence: Have I Been Pwned
    https://haveibeenpwned.com/API/v3
    """

    def __init__(self, key):
        self.key = key
        self.ua = 'HappyHunting'
        self.urls = {
            'account': 'https://haveibeenpwned.com/api/v3/breachedaccount/{}'
        }

    async def _request(self, session, url, params={}):
        '''
        @description: Request HIBP API
        @param {object} session
        @param {str} url
        @param {dict} params
        @return {*}
        ''' 
        
        self.results = []
        headers = {'User-Agent': self.ua, 'hibp-api-key': self.key}
        async with session.get(url, headers=headers) as resp:
            assert resp.status == 200
            r = await resp.json()
            self.ioc = url.split('/')[-1]
            await self._parser(r)
            
    async def _parser(self, r):
        '''
        @Description: Parse API results
        @Date: 2021-06-05 14:59:04
        @param {dict} r
        @return {*}
        '''

        if self.parser_module == 'account':
            if r:
                await self.parser_breaches_account(r)
        else:
            print("I didn't do anything!")

    async def get_indicators(self, data, type, **kwargs):
        '''
        @Description: Get threat intelligence
        @Date: 2021-06-06 08:34:18
        @param {list} data
        @param {str} type: account
        @return {list}
        '''

        self.parser_module = type
        if type == 'account':
            return await self.get_breaches_account(data)

    async def get_breaches_account(self, data):
        '''
        @Description: Get breaches account
        @Date: 2021-06-05 14:55:53
        @param {list} data
        @return {list}
        '''
        
        async with aiohttp.ClientSession() as session:
            task_list = []
            for ioc in data:
                url = self.urls['account'].format(ioc)
                req = self._request(session, url)
                task = asyncio.create_task(req)
                task_list.append(task)
            await asyncio.gather(*task_list, return_exceptions=True)
            return self.results

    async def parser_breaches_account(self, r):
        '''
        @Description: Parse breaches account results
        @Date: 2021-06-05 15:01:50
        @param dict r
        @return {list}
        '''

        data = {
            'ioc': self.ioc,
            'tags': [ i['Name'] for i in r ]
        }
        self.results.append(data)