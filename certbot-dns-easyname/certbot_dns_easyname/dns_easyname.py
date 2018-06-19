"""DNS Authenticator for Easyname DNS."""
import json
import logging

import base64
import hashlib
import urllib
import time
import requests

import httplib2
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

BASE_URL = 'https://api.easyname.com'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
	"""DNS Authenticator for Easyname DNS

	This Authenticator uses the Easyname DNS API to fulfill a dns-01 challenge.
	"""

	description = ('Obtain certificates using a DNS TXT record (if you are using Easyname '
				   'for DNS).')
	ttl = 60

	def __init__(self, *args, **kwargs):
		super(Authenticator, self).__init__(*args, **kwargs)
		self.credentials = None

	@classmethod
	def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
		super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=30)
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
		return _EasyNameAPIClient(self.conf('credentials'), BASE_URL)


class _EasyNameAPIClient(object):
	"""
	Encapsulates all communication with the Easyname API.
	"""

	def __init__(self, configuration, base_url):
		self.configuration = configuration
		self.base_url = base_url

	def get_api_authentication(self):
		"""
		Returns the value for the X-User-Authentication header
		"""
		m = hashlib.md5()
		m.update(self.configuration.conf('api-auth-salt') % (self.configuration.conf('user-id'), self.configuration.conf('email')))
		return base64.b64encode(m.digest())
			
	def get_request_signature(self, data, timestamp):
		"""
		Returns the value for the signature key of the body
		"""
		keys = data.keys()
		keys.append(['timestamp'])
		keys.sort()
		
		string = ''
		for key in keys:
			if key is 'timestamp':
				string += str(timestamp)
			else:
				string += str(data[key])
		
		stringlen = len(string)
		pos = int(stringlen/2)
		if stringlen%2 == 1:
			pos += 1
		
		m = hashlib.md5()
		m.update(string[:pos] + self.configuration.conf('api-signing-salt') + string[pos:])
		return base64.b64encode(m.digest())
		
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
		return urllib.urlencode(json.dumps(body))
	
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
		
		if method is 'GET':
			resp = requests.get(url, headers=headers)
		elif method is 'POST':
			resp = requests.post(url, headers=headers, data=self.create_request_body(data))
		else:
			raise errors.PluginError('Unknown request method {0}.'.format(method))
		
		return json.loads(resp)
	
	def list_domains(self, limit=10, offset=0):
		"""
		Requests a list of all active domains
		"""
		return self.do_request('GET', 'domain?offset={0}&limit={1}'.format(offset, limit))
	
	def get_domain(self, domain_name):
		"""
		Get the specified domain document
		"""
		domains = self.list_domains(100, 0)
		for i in domains:
			domain = domains[i]
			if domain['domain'] is domain_name:
				return domain
				
		raise errors.PluginError('Domain not found: {0}'.format(domain_name))
	
	def create_dns(self, domain_name, name, type, content, priority, ttl):
		"""
		Adds a DNS entry to the specified domain
		"""
		domain = self.get_domain(domain_name)
		return self.do_request('POST', 'domain/{0}/dns'.format(domain['id']), {
			'name': name,
			'type': type,
			'content': content,
			'priority': priority,
			'ttl': ttl
		})
	
	def list_dns(self, domain_name, limit=10, offset=0):
		"""
		Get all DNS entries of the specified domain
		"""
		domain = self.get_domain(domain_name)
		return self.do_request('GET', 'domain/{0}/dns?offset={1}&limit={2}'.format(domain['id'], offset, limit), {
			'name': name,
			'type': type,
			'content': content,
			'priority': priority,
			'ttl': ttl
		})
	
	def delete_dns(self, domain_name, name, type, content):
		"""
		Deletes a DNS entry on the specified domain, if found
		"""
		domain = self.get_domain(domain_name)
		entries = self.list_dns(domain['id'])
		
		for i in entries:
			entry = entries[i]	
			if entry['name'] is name and entry['type'] is type and entry['content'] is content:
				return self.do_request('POST', 'domain/{0}/dns/{1}/delete'.format(domain['id'], entry['id']))
				
		raise errors.PluginError('DNS entry not found ({0}): {1}, {2}, {3}'.format(domain_name, name, type, content))
