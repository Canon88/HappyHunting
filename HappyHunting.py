'''
Author: Canon
Date: 2020-10-09 17:18:58
LastEditTime: 2021-06-09 00:26:07
'''

import os

from lib.siem import SIEM
from lib.hibp import HIBP
from lib.threatbook import ThreatBook
from lib.passivetotal import PassiveTotal
from lib.shodan import Shodan
from lib.proxycheck import ProxyCheck
from lib.virustotal import Virustotal
from lib.alienvault import OTX
from config.config import Config


config = Config()
dirname = os.path.dirname(os.path.realpath(__file__))
yaml = os.path.join(dirname, 'config/config.yaml')
base_conf = config.load(yaml)
intel_conf = base_conf['intelligence']
enrich_conf = base_conf['enrichment']


class Enrichment():
    def __init__(self):
        pass

    async def get_result_from_passivetotal(self, ioc, sub, **kwargs):
        user = enrich_conf['passivetotal']['user']
        key = enrich_conf['passivetotal']['key']
        pt = PassiveTotal(user, key)
        results = await pt.main(ioc, sub, **kwargs)
        return results

    async def get_result_from_shodan(self, ioc, sub, **kwargs):
        key = enrich_conf['shodan']['key']
        shodan = Shodan(key)
        results = await shodan.main(ioc, sub)
        return results

    async def info(self, ioc, provider, sub, **kwargs):
        data = []
        if provider == 'riskiq':
            data = await self.get_result_from_passivetotal(ioc, sub, **kwargs)
        elif provider == 'shodan':
            data = await self.get_result_from_shodan(ioc, sub, **kwargs)
        else:
            print("I didn't do anything.")
        return data


class Intelligence():
    def __init__(self):
        pass

    async def get_result_from_hibp(self, ioc, sub):
        key = intel_conf['hibp']['key']
        hibp = HIBP(key)
        results = await hibp.get_indicators(ioc, sub)
        return results

    async def get_result_from_proxycheck(self, ioc, sub, **kwargs):
        key = intel_conf['proxycheck']['key']
        proxycheck = ProxyCheck(key)
        results = await proxycheck.main(ioc, sub)
        return results

    async def get_result_from_threatbook(self, ioc, sub, **kwargs):
        key = intel_conf['threatbook']['key']
        tb = ThreatBook(key)
        results = await tb.main(ioc, sub)
        return results

    async def get_result_from_virustotal(self, ioc, sub, **kwargs):
        key = intel_conf['virustotal']['key']
        vt = Virustotal(key)
        results = await vt.main(ioc, sub)
        return results

    async def get_result_from_alienvault(self, ioc, sub, **kwargs):
        key = intel_conf['alienvault']['key']
        otx = OTX(key)
        results = await otx.main(ioc, sub, **kwargs)
        return results

    async def threat(self, ioc, provider, sub, **kwargs):
        if provider == 'proxycheck':
            threats = await self.get_result_from_proxycheck(ioc, sub, **kwargs)
        elif provider == 'threatbook':
            threats = await self.get_result_from_threatbook(ioc, sub, **kwargs)
        elif provider == 'virustotal':
            threats = await self.get_result_from_virustotal(ioc, sub, **kwargs)
        elif provider == 'alienvault':
            threats = await self.get_result_from_alienvault(ioc, sub, **kwargs)
        elif provider == 'hibp':
            threats = await self.get_result_from_hibp(ioc, sub, **kwargs)
        else:
            print("I didn't do anything.")
        return threats