'''
Author: Canon
Date: 2020-11-25 15:04:32
LastEditTime: 2021-06-09 00:20:57
'''

import aiohttp
import asyncio


class OTX():
    """
    Threat intelligence: Alienvault
    https://otx.alienvault.com/api
    """

    def __init__(self, key):
        self.ua = 'HappyHunting'
        self.urls = {
            'user': 'https://otx.alienvault.com/api/v1/users/me',
            'indicators': 'https://otx.alienvault.com/api/v1/indicators/{IndicatorType}/{ioc}/{section}'
        }
        self.key = key

    async def _request(self, session, url, params={}):
        '''
        @Description: Request Alienvault API
        @Date: 2021-06-05 15:04:46
        @param {object} session
        @param {str} url
        @param {dict} params
        @return {*}
        '''

        self.results = []
        headers = {
            'User-Agent': self.ua,
            'Content-Type': 'application/json',
            'X-OTX-API-KEY': self.key
        }
        async with session.get(url, headers=headers, params=params) as resp:
            assert resp.status == 200
            r = await resp.json()
            self.ioc = url.split('/')[-2]
            await self._parser(r)

    async def _parser(self, r):
        '''
        @Description: Parse API results
        @Date: 2021-06-05 15:04:20
        @param {dict} r
        @return {*}
        '''

        if self.parser_module == 'nids':
            await self.parser_nids(r)
        elif self.parser_module in ['ip', 'domain', 'hash', 'hostname', 'url']:
            await self.parser_indicators(r)
        else:
            print("I didn't do anything!")

    async def get_indicators(self, data, **kwargs):
        '''
        @Description: Get threat intelligence
        @Date: 2021-06-05 15:05:40
        @param {list} data
        @param {str} type: ip、domain、hash、hostname、url、nids
        @param {object} kwargs
        @param {str} type
        @return {list}
        '''

        params = {
            'page': kwargs.get('page', 1),
            'limit': kwargs.get('limit', 10)
        }
        async with aiohttp.ClientSession() as session:
            task_list = []
            for ioc in data:
                IndicatorType, section = self.query_string(ioc, self.parser_module)
                url = self.urls['indicators'].format(
                    IndicatorType=IndicatorType, ioc=ioc, section=section)
                req = self._request(session, url, params)
                task = asyncio.create_task(req)
                task_list.append(task)
            await asyncio.gather(*task_list, return_exceptions=True)
            return self.results

    async def parser_indicators(self, r):
        '''
        @Description: Parse threat intelligence results
        @Date: 2021-06-05 15:42:29
        @param {dict} r
        @return {list}
        '''
        pulses = r['pulse_info']['pulses']
        ioc = r['base_indicator'].get('indicator')
        for pulse in pulses:
            results = {
                'ioc': ioc,
                'description': pulse['description'],
                'name': pulse['name'],
                'tags': pulse['tags'],
                'malware_families': pulse['malware_families'],
                'is_modified': pulse['is_modified'],
                'references': pulse['references'],
                'created': pulse['created'],
                'modified': pulse['modified']
            }
            self.results.append(results)

    async def parser_nids(self, r):
        '''
        @Description: Parse nids results
        @Date: 2021-06-05 15:49:00
        @param {dict} r
        @return {list}
        '''
        results = {
            'ioc': self.ioc,
            'count': r['count'],
            'results': r['results']
        }
        self.results.append(results)

    def is_ip(self, ip):
        '''
        @Description: Check IP
        @Date: 2021-06-05 15:57:17
        @param {str} ip
        @return {bool}
        '''
        try:
            if len(ip.split('.')) == 4:
                return True
            else:
                return False
        except:
            return False

    def query_string(self, ioc, type):
        section = 'general'
        if type == 'nids':
            if self.is_ip(ioc):
                section = 'nids_list'
                IndicatorType = 'IPv4'
            else:
                section = 'ip_list'
                IndicatorType = 'nids'
        elif type == 'ip':
            IndicatorType = 'IPv4'
        elif type == 'hash':
            IndicatorType = 'file'
        else:
            IndicatorType = type
        return IndicatorType, section

    async def main(self, data, type, **kwargs):
        self.parser_module = type
        if self.parser_module in ['ip', 'domain', 'hash', 'hostname', 'url', 'nids']:
            return await self.get_indicators(data, **kwargs)
        else:
            pass