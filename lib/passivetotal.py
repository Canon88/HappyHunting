'''
Author: Canon
Date: 2020-11-09 15:29:36
LastEditTime: 2021-06-09 00:22:07
'''

import asyncio
import aiohttp
from aiohttp import BasicAuth as auth


class PassiveTotal():
    def __init__(self, user, key):
        self.user = user
        self.key = key
        self.ua = "HappyHunting"
        self.urls = {
            'api': {
                'whois': 'https://api.passivetotal.org/v2/whois',
                'pdns': 'https://api.passivetotal.org/v2/dns/passive',
                'subdomains': 'https://api.passivetotal.org/v2/enrichment/subdomains'
            },
            'evil': {
                'whois': 'https://community.riskiq.com/api/whois',
                'pdns': 'https://community.riskiq.com/api/resolutions',
                'subdomains': 'https://community.riskiq.com/api/dns/passive/subdomains'
            }
        }

    async def _request(self, session, url, params):
        self.results = []
        headers = {'Content-Type': 'application/json', 'User-Agent': self.ua}
        async with session.get(url, auth=auth(self.user, self.key), params=params, headers=headers) as resp:
            assert resp.status == 200
            r = await resp.json()
            await self._parser(r, **params)

    async def _parser(self, r, **kwargs):
        if self.parser_module == 'whois':
            await self.parser_whois(r, **kwargs)
        elif self.parser_module == 'pdns':
            await self.parser_passive(r, **kwargs)
        elif self.parser_module == 'subdomains':
            await self.parser_subdomains(r, **kwargs)
        else:
            print("I didn't do anything!")

    async def _request_evil(self, session, url, params, headers):
        self.results = []
        async with session.get(url, params=params, headers=headers) as resp:
            assert resp.status == 200
            r = await resp.json()
            await self._parser(r, **params)        

    async def get_whois(self, data, history=False, **kwargs):
        url = self.urls['api'][self.parser_module]
        self.evil = False
        if kwargs.get('evil'):
            self.evil = True
            url = self.urls['evil'][self.parser_module]
            headers = kwargs.get('headers', {})

        async with aiohttp.ClientSession() as session:
            task_list = []
            for ioc in data:
                params = {'query': ioc, 'history': str(history).lower()}
                if self.evil:
                    req = self._request_evil(session, url, params, headers)
                else:
                    req = self._request(session, url, params)
                task = asyncio.create_task(req)
                task_list.append(task)
            await asyncio.gather(*task_list, return_exceptions=True)
        return self.results

    async def parser_whois(self, r, **kwargs):
        text = 'rawText'
        if self.evil:
            text = 'text'

        if kwargs['history'] == 'true':
            for i in r['results']:
                if i.get(text):
                    del i[text]
                i['ioc'] = kwargs['query']
                self.results.append(i)
        else:
            del r[text]
            r['ioc'] = kwargs['query']
            self.results.append(r)

    async def get_passive(self, data, **kwargs):
        url = self.urls['api'][self.parser_module]
        self.evil = False
        if kwargs.get('evil'):
            self.evil = True
            url = self.urls['evil'][self.parser_module]
            headers = kwargs.get('headers', {})

        async with aiohttp.ClientSession() as session:
            task_list = []
            for ioc in data:
                params = {'query': ioc}
                if self.evil:
                    params['pageSize'] = kwargs.get('size', 50)
                    req = self._request_evil(session, url, params, headers)
                else:
                    req = self._request(session, url, params)
                task = asyncio.create_task(req)
                task_list.append(task)
            await asyncio.gather(*task_list, return_exceptions=True)
        return self.results

    async def parser_passive(self, r, **kwargs):
        if self.evil:
            results = {
                'ioc': kwargs['query'],
                'domain': list(r['resolutions'].keys())
            }
            self.results.append(results)
        else:
            for i in r['results']:
                if i['resolveType'] == 'domain':
                    i['totalRecords'] = r['totalRecords']
                    i['ioc'] = i.pop('value')
                    i['type'] = r['queryType']
                    self.results.append(i)

    async def get_subdomains(self, data, **kwargs):
        url = self.urls['api'][self.parser_module]
        self.evil = False
        if kwargs.get('evil'):
            self.evil = True
            url = self.urls['evil'][self.parser_module]
            headers = kwargs.get('headers', {})

        async with aiohttp.ClientSession() as session:
            task_list = []
            for ioc in data:
                params = {'query': ioc}
                if self.evil:
                    req = self._request_evil(session, url, params, headers)
                else:
                    req = self._request(session, url, params)
                task = asyncio.create_task(req)
                task_list.append(task)
            await asyncio.gather(*task_list, return_exceptions=True)
        return self.results

    async def parser_subdomains(self, r, **kwargs):
        if self.evil:
            results = {
                'ioc': kwargs['query'],
                'subdomains': [i['hostname'] for i in r['results']],
                'count': len([i['hostname'] for i in r['results']])
            }
        else:
            results = {
                'ioc': kwargs['query'],
                'primarydomain': r['primaryDomain'],
                'subdomains': [subDomain + '.' + r['primaryDomain'] for subDomain in r['subdomains']],
                'count': len(r['subdomains'])
            }
        self.results.append(results)

    async def main(self, data, type, **kwargs):
        self.parser_module = type
        if self.parser_module == 'whois':
            return await self.get_whois(data, **kwargs)
        elif self.parser_module == 'pdns':
            return await self.get_passive(data, **kwargs)
        elif self.parser_module == 'subdomains':
            return await self.get_subdomains(data, **kwargs)
        else:
            pass