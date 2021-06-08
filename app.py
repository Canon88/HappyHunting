'''
Author: Canon
Date: 2021-05-28 23:19:35
LastEditTime: 2021-06-07 22:57:17
'''

import logging
from aiohttp import web

from HappyHunting import Enrichment, Intelligence

intel = Intelligence()
enrich = Enrichment()

routes = web.RouteTableDef()
@routes.get('/hunting/api/{module}')
async def get_handler(request):
    query = { k: v for k, v in request.query.items()}
    query['ioc'] = [query['ioc']]
    if request.match_info.get('module') == 'intelligence':
        data = await intel.threat(**query)
    elif request.match_info.get('module') == 'enrichment':
        data = await enrich.info(**query)
    else:
        pass
    return web.json_response(data)

app = web.Application()
app.add_routes(routes)
if __name__ == "__main__":
    logging.basicConfig(filename='./access.log', level=logging.INFO)
    web.run_app(app, port=9527)