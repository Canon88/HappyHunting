'''
Author: Canon
Date: 2020-11-20 10:04:45
LastEditTime: 2021-06-09 00:23:35
'''

import datetime
import aiohttp
import asyncio


class Virustotal():
    """
    Threat intelligence: Virustotal
    https://developers.virustotal.com/v3.0/reference
    """

    def __init__(self, key):
        self.ua = "HappyHunting"
        self.urls = {
            'hash': 'https://www.virustotal.com/api/v3/files/{}',
            'ip': 'https://www.virustotal.com/api/v3/ip_addresses/{}',
            'domain': 'https://www.virustotal.com/api/v3/domains/{}'
        }
        self.q = asyncio.Queue()
        [self.q.put_nowait(k) for k in key]

    async def _request(self, session, url, params={}):
        '''
        @Description: Request Virustotal API
        @Date: 2021-06-05 18:57:26
        @param {object} session
        @param {str} url
        @param {dict} params
        @return {*}
        '''
        self.results = []
        key = await self.q.get()
        headers = {'User-Agent': self.ua, 'x-apikey': key}
        await self.q.put(key)
        async with session.get(url, headers=headers, params=params) as resp:
            assert resp.status == 200
            r = await resp.json()
            await self._parser(r['data'])

    async def _parser(self, r):
        '''
        @Description: Parse API results
        @Date: 2021-06-05 18:59:24
        @param {dict} r
        @return {*}
        '''        
        if self.parser_module == 'hash':
            await self.parser_hash(r)
        elif self.parser_module == 'ip':
            await self.parser_ip(r)
        elif self.parser_module == 'domain':
            await self.parser_domain(r)
        else:
            print("I didn't do anything!")

    async def get_indicators(self, data):
        '''
        @Description: Get threat intelligence
        @Date: 2021-06-06 00:57:19
        @param {list} data
        @param {str} type
        @return {*}
        '''
        
        async with aiohttp.ClientSession() as session:
            task_list = []
            for ioc in data:
                url = self.urls[self.parser_module].format(ioc)
                req = self._request(session, url)
                task = asyncio.create_task(req)
                task_list.append(task)
            await asyncio.gather(*task_list, return_exceptions=True)
            return self.results

    async def parser_ip(self, r):
        '''
        @Description: Parse IP results
        @Date: 2021-06-06 09:14:27
        @param {dict} r
        @return {list}
        '''
        results = {
            'ioc': r['id'],
            'tags': r['attributes']['tags'],
            'harmless': r['attributes']['last_analysis_stats']['harmless'],
            'malicious': r['attributes']['last_analysis_stats']['malicious'],
            'undetected': r['attributes']['last_analysis_stats']['undetected'],
            'reputation': r['attributes']['reputation'],
            'last_modification_date': self.stamp2date(r['attributes']['last_modification_date'])
        }
        self.results.append(results)

    async def parser_domain(self, r):
        '''
        @Description: Parse Domain results
        @Date: 2021-06-06 09:14:14
        @param {dict} r
        @return {list}
        '''
        results = {
            'ioc': r['id'],
            'tags': r['attributes']['tags'],
            'harmless': r['attributes']['last_analysis_stats']['harmless'],
            'malicious': r['attributes']['last_analysis_stats']['malicious'],
            'undetected': r['attributes']['last_analysis_stats']['undetected'],
            'last_dns_records': r['attributes']['last_dns_records'],
            'last_dns_records_date': self.stamp2date(r['attributes']['last_dns_records_date']),
            'last_modification_date': self.stamp2date(r['attributes']['last_modification_date']),
            'last_update_date': self.stamp2date(r['attributes']['last_update_date'])
        }
        self.results.append(results)

    async def parser_hash(self, r):
        '''
        @Description: Parse HASH results
        @Date: 2021-06-06 09:13:57
        @param {dict} r
        @return {list}
        '''
        results = {
            'ioc': r['id'],
            'tags': r['attributes']['tags'],
            'harmless': r['attributes']['last_analysis_stats']['harmless'],
            'malicious': r['attributes']['last_analysis_stats']['malicious'],
            'undetected': r['attributes']['last_analysis_stats']['undetected'],
            'type_extension': r['attributes']['type_extension'],
            'md5': r['attributes']['md5'],
            'sha1': r['attributes']['sha1'],
            'sha256': r['attributes']['sha256'],
            'first_submission_date': self.stamp2date(r['attributes']['first_submission_date']),
            'last_modification_date': self.stamp2date(r['attributes']['last_modification_date']),
            'last_analysis_date': self.stamp2date(r['attributes']['last_analysis_date'])
        }
        self.results.append(results)

    def stamp2date(self, timestamp):
        '''
        @Description: Timestamp to str
        @Date: 2021-06-06 09:14:55
        @param {object} timestamp
        @return {str}
        '''
        return datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

    async def main(self, data, type):
        self.parser_module = type
        if self.parser_module in ['ip', 'domain', 'hash']:
            return await self.get_indicators(data)
        else:
            pass