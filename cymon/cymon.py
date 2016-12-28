import json
import requests
from urllib import quote_plus


class Cymon(object):

    def __init__(self, auth_token=None, endpoint='https://cymon.io/api/nexus/v1'):
        self.endpoint = endpoint
        self.session = requests.Session()
        self.session.headers = {
            'content-type': 'application/json',
            'accept': 'application/json',
        }
        if auth_token:
            self.session.headers.update({'Authorization': 'Token {0}'.format(auth_token)})

    def get(self, method, params=None):
        r = self.session.get(self.endpoint + method, params=params)
        r.raise_for_status()
        return r

    def post(self, method, params, headers=None):
        r = self.session.post(self.endpoint + method, data=json.dumps(params), headers=headers)
        r.raise_for_status()
        return r

    def get_paginator(self, method):
        """
        Returns a Paginator class to use for handling API pagination.
        """
        method = method.lower()
        if self._can_paginate(method):
            return Paginator(self, method)
        else:
            raise NoPaginatorError('Cannot paginate {} method'.format(method))

    def _can_paginate(self, method):
        """
        Basic check to raise exception when method cannot paginate.
        """
        if method in ['ip_events', 'ip_events', 'ip_urls', 'ip_blacklist']:
            return True
        else:
            return False

    def ip_lookup(self, ip_addr):
        r = self.get('/ip/' + ip_addr)
        return json.loads(r.text)

    def ip_events(self, ip_addr):
        r = self.get('/ip/' + ip_addr + '/events')
        return json.loads(r.text)

    def ip_domains(self, ip_addr):
        r = self.get('/ip/' + ip_addr + '/domains')
        return json.loads(r.text)

    def ip_urls(self, ip_addr): 
        r = self.get('/ip/' + ip_addr + '/urls')
        return json.loads(r.text)

    def domain_lookup(self, name):
        r = self.get('/domain/' + name)
        return json.loads(r.text)

    def url_lookup(self, location):
        r = self.get('/url/' + quote_plus(location))
        return json.loads(r.text)

    def ip_blacklist(self, tag, days=1, limit=10, offset=0):
        ''' supported tags: malware, botnet, spam, phishing, dnsbl, blacklist '''
        r = self.get('/blacklist/ip/' + tag + '/?days=%d&limit=%d&offset=%d' %(days,limit,offset))
        return json.loads(r.text)

    def domain_blacklist(self, tag, days=1, limit=10, offset=0):
        ''' supported tags: malware, botnet, spam, phishing, dnsbl, blacklist '''
        r = self.get('/blacklist/domain/' + tag + '/?days=%d&limit=%d&offset=%d' %(days,limit,offset))
        return json.loads(r.text)


class Paginator(object):
    """
    This class uses generators to provide an iterable object for performing
        recusive API calls when a result has been paginated.
    """
    def __init__(self, cymon, method):
        self.cymon = cymon
        self.method = method

    def paginate(self, *args, **kwargs):
        """
        Use Cymon client object to make recursive API calls when
            result is paginated.
        """
        method_to_call = getattr(self.cymon, self.method)
        result = method_to_call(*args, **kwargs)
        if result['next'] is not None:
            has_next = True
        yield result['results'] # intial API call to start recursion
        while has_next:
            resp = requests.get(result['next'])
            result = json.loads(resp.text)
            if result['next'] is None:
                has_next = False
            yield result['results']


class NoPaginatorError(Exception):
    pass
