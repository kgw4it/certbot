"""DNS Authenticator for Easyname DNS."""
import json
import logging

import base64
import hashlib
import urllib
import time
import requests
import re
from lxml import etree

import httplib2
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

BASE_URL_API = 'https://api.easyname.com'
BASE_URL_WEB = 'https://my.easyname.com'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Easyname DNS

    This Authenticator uses the Easyname DNS API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are using Easyname '
                   'for DNS).')
    ttl = 300
    easyname_client = None

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=60)
        add('credentials',
            help=('Path to Easyname DNS configuration file'),
            default=None)

    def more_info(self): # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the Easyname DNS API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Easyname credentials INI file',
            {
                'user-id': 'user-id associated with your Easyname account',
                'email': 'email address associated with your Easyname account',
                'password': 'password associated with your Easyname account',
                'api-key': 'API Key found on the API Credentials Page',
                'api-auth-salt': 'API Authentication Salt found on the API Credentials Page',
                'api-signing-salt': 'API Signing Salt found on the API Credentials Page'
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_easyname_api_client().create_dns(domain, validation_name, 'txt', validation, 10, self.ttl)

    def _cleanup(self, domain, validation_name, validation):
        self._get_easyname_api_client().delete_dns(domain, validation_name, 'txt', validation)

    def _get_easyname_api_client(self):
        if self.easyname_client is None:
            self.easyname_client = _EasyNameAPIClient(self.credentials, BASE_URL_API, BASE_URL_WEB)
        return self.easyname_client


class _EasyNameAPIClient(object):
    """
    Encapsulates all communication with the Easyname API.
    """

    def __init__(self, configuration, base_url_api, base_url_web):
        self.configuration = configuration
        self.base_url = base_url_api
        self.base_url_web = base_url_web
        self.web_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.87 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Referer': self.base_url_web
        }
        
        # do a request to get the seesion id cookie and the loginxtoken
        url_login = self.base_url_web + '/de/anmelden'        
        resp_out = requests.get(url_login, headers=self.web_headers)
        
        if resp_out.status_code != 200:
            raise errors.PluginError('Request to get Session Cookie failed with status code {0}'.format(resp_out.status_code))
        
        self.web_cookies = {
            'ENSID': resp_out.cookies['ENSID']
        }
        
        # get the loginxtoken from the markup
        minput = re.search("name=\"loginxtoken\" value=\"([0-9a-f]+)\"", resp_out.text.encode('utf-8'))
        loginxtoken = minput.group(1)
        
        # do the login (upgrades the session id to logged in)
        data_login = {
            'username': self.configuration.conf('email'),
            'password': self.configuration.conf('password'),
            'submit': '',
            'loginxtoken': loginxtoken
        }
        
        resp_login = requests.post(url_login, headers=self.web_headers, cookies=self.web_cookies, data=data_login, allow_redirects=False)
        
        if resp_login.status_code != 302:
            req = resp_login.request

            command = "curl -X {method} -H {headers} -d '{data}' '{uri}'"
            method = req.method
            uri = req.url
            data = req.body
            headers = ['"{0}: {1}"'.format(k, v) for k, v in req.headers.items()]
            headers = " -H ".join(headers)
            curl_cmd = command.format(method=method, headers=headers, data=data, uri=uri)
            raise errors.PluginError('Request to login failed with status code: {0}\n\n\n{1}\n{2}\n{3}'.format(curl_cmd, resp_login.status_code, json.dumps(dict(resp_login.headers)), resp_login.text.encode('utf-8')))
        
        # update cookies
        self.web_cookies = {
            'ENSID': resp_login.cookies['ENSID']
        }

    def get_api_authentication(self):
        """
        Returns the value for the X-User-Authentication header
        """
        m = hashlib.md5()
        m.update(self.configuration.conf('api-auth-salt') % (self.configuration.conf('user-id'), self.configuration.conf('email')))
        return base64.b64encode(m.hexdigest())
            
    def get_request_signature(self, data, timestamp):
        """
        Returns the value for the signature key of the body
        """
        keys = data.keys()
        keys.append('timestamp')
        keys.sort()
        
        string = ''
        for key in keys:
            if key == 'timestamp':
                string += str(timestamp)
            else:
                string += str(data[key])
        
        stringlen = len(string)
        pos = int(stringlen/2)
        if stringlen%2 == 1:
            pos += 1
        
        m = hashlib.md5()
        m.update(string[:pos] + self.configuration.conf('api-signing-salt') + string[pos:])
        return base64.b64encode(m.hexdigest())
        
    def create_request_body(self, data):
        """
        Returns the full request body from the data
        """
        timestamp = int(time.time())
        body = {
            'data': data,
            'timestamp': timestamp,
            'signature': self.get_request_signature(data, timestamp)
        }
        return json.dumps(body)
    
    def do_request(self, method, path, data):
        """
        Does a request against the supplied path using the
        provided data
        """
        url = self.base_url + '/' + path
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-User-ApiKey': self.configuration.conf('api-key'),
            'X-User-Authentication': self.get_api_authentication()
        }
        
        if method == 'GET':
            resp = requests.get(url, headers=headers)
        elif method == 'POST':
            resp = requests.post(url, headers=headers, data=self.create_request_body(data))
        else:
            raise errors.PluginError('Unknown request method {0}.'.format(method))
        
        if resp.status_code != 200:
            raise errors.PluginError('Request failed with status code {0}: {1}'.format(resp.status_code, resp.text))
        
        return resp.json()['data']
    
    def list_domains(self, limit=10, offset=0):
        """
        Requests a list of all active domains
        """
        return self.do_request('GET', 'domain?offset={0}&limit={1}'.format(offset, limit), {})
    
    def get_domain(self, domain_name):
        """
        Get the specified domain document
        """
        domains = self.list_domains(100, 0)
        zone_name_guesses = dns_common.base_domain_name_guesses(domain_name)
        for domain in domains:
            if domain['domain'] in zone_name_guesses:
                return domain
                
        raise errors.PluginError('Domain not found: {0}'.format(domain_name))
    
    def create_dns(self, domain_name, name, type, content, priority, ttl):
        """
        Adds a DNS entry to the specified domain
        """
        domain = self.get_domain(domain_name)
        
        url_create_dns = self.base_url_web + '/domains/settings/form.php?domain={0}'.format(domain['id'])
        data_create_dns = {
            'id': '',
            'action': 'save',
            'name': name.replace('.' + domain['domain'], ''),
            'type': type.upper(),
            'content': content,
            'prio': priority,
            'ttl': ttl,
            'commit': ''
        }

        resp_create = requests.post(url_create_dns, headers=self.web_headers, cookies=self.web_cookies, data=data_create_dns)
        success = re.search('cp_domains_dnseintraege', resp_create.text.encode('utf-8'))
        
        if success is None or len(success.group(0)) == 0:
            raise errors.PluginError('Request to create dns entry failed: No success page: {0}'.format(resp_create.text.encode('utf-8')))
        
        if resp_create.status_code != 200:
            raise errors.PluginError('Request to create dns entry failed with status code {0}'.format(resp_create.status_code))
        
        return {
            'success': True
        }
    
    def list_dns(self, domain, limit=100, offset=0):
        """
        Get all DNS entries of the specified domain
        """
        url_list_dns = self.base_url_web + '/domains/settings/dns.php?domain={0}'.format(domain['id'])
        resp_list = requests.get(url_list_dns, headers=self.web_headers, cookies=self.web_cookies)
        success = re.search('cp_domains_dnseintraege', resp_list.text.encode('utf-8'))
        
        if success is None or len(success.group(0)) == 0:
            raise errors.PluginError('Request to list dns entry failed: No success page: {0}'.format(resp_create.text.encode('utf-8')))
        
        table = etree.HTML(resp_list.text.encode('utf-8')).xpath('//table[@id="cp_domains_dnseintraege"]//tr')
        rows = iter(table)
        resp = []
        for r in rows:
            try:
                row = etree.HTML(etree.tostring(r))
                id = re.search('&id=([0-9]+)', row.xpath('//@ondblclick')[0]).group(1)
                name = row.xpath('//td[1]/text()')[0].strip()
                type = row.xpath('//td[2]/text()')[0].strip()
                content = row.xpath('//td[3]/text()')[0].strip()
                resp.append({
                    'id': id,
                    'name': name,
                    'type': type,
                    'content': content
                })
            except:
                pass
        
        return resp
    
    def delete_dns(self, domain_name, name, type, content):
        """
        Deletes a DNS entry on the specified domain, if found
        """
        domain = self.get_domain(domain_name)
        entries = self.list_dns(domain)
        
        print "To be removed: {0}, {1}, {2}, {3}".format(domain_name, name, type, content)
        for entry in entries:
            print "Processing: {0}, {1}, {2}".format(entry['name'], entry['type'], entry['content'])
            if entry['name'] == name and entry['type'].upper() == type.upper() and entry['content'] == content:
                print "Removing entry"
                url_del_dns = self.base_url_web + '/domains/settings/delete_record.php?domain={0}&id={1}&confirm=1'.format(domain['id'], entry['id'])
                resp_list = requests.get(url_del_dns, headers=self.web_headers, cookies=self.web_cookies)
                
        return {
            'success': True
        }
