"""DNS Authenticator for W4DNS."""
import logging

import httplib2
import requests
from urllib.parse import urlencode
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)

ACCOUNT_URL = 'https://dns.w4it.at/settings'
W4DNS_BASE_URL = 'https://api-dns.w4it.at/v1'

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for W4DNS

    This Authenticator uses the W4DNS API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are using W4DNS for '
                   'DNS).')
    ttl = 300

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=30)
        add('credentials', help='W4DNS credentials INI file.')

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the W4DNS API.'

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'W4DNS credentials INI file',
            {
                'api-key': 'API key for W4DNS account, obtained from {0}'.format(ACCOUNT_URL)
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_w4dns_client().add_txt_record(domain, validation_name, validation, self.ttl)

    def _cleanup(self, domain, validation_name, validation):
        self._get_w4dns_client().del_txt_record(domain, validation_name, validation)

    def _get_w4dns_client(self):
        return _W4DNSClient(self.credentials.conf('api-key'))


class _W4DNSClient(object):
    """
    Encapsulates all communication with the W4DNS API.
    """

    def __init__(self, api_key):
        self.api_key = api_key

    def add_txt_record(self, domain, record_name, record_content, record_ttl):
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the W4DNS domain.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the W4DNS API
        """

        try:
            domaindoc = self._find_domain(domain)
        except errors.PluginError as e:
            logger.debug('Encountered error finding domain_id during addition: %s', e)
            raise e

        data = {'type': 'TXT',
                'name': record_name.replace('.' + domaindoc['name'], ''),
                'content': record_content,
                'ttl': record_ttl}

        try:
            logger.debug('Attempting to add record to domain %s: %s', domaindoc['_id'], data)
            self._add_dns_record(domaindoc['_id'], data=data)
        except errors.PluginError as e:
            logger.error('Encountered W4DNS API Error adding TXT record: %d %s', e, e)
            raise e

    def del_txt_record(self, domain, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        Note that both the record's name and content are used to ensure that similar records
        created concurrently (e.g., due to concurrent invocations of this plugin) are not deleted.

        Failures are logged, but not raised.

        :param str domain: The domain to use to look up the W4DNS domain.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        """

        try:
            domaindoc = self._find_domain(domain)
        except errors.PluginError as e:
            logger.debug('Encountered error finding domain_id during deletion: %s', e)
            raise e

        try:
            record_id = self._find_txt_record_id(domaindoc['_id'], record_name.replace('.' + domaindoc['name'], ''), record_content)
            logger.debug('Successfully found TXT record with record_id: %s', record_id)
        except errors.PluginError as e:
            logger.error('Encountered W4DNS API Error looking up TXT record: %d %s', e, e)
            raise e

        try:
            self._delete_dns_record(domaindoc['_id'], record_id)
            logger.debug('Successfully deleted TXT record.')
        except errors.PluginError as e:
            logger.warning('Encountered W4DNS API Error deleting TXT record: %s', e)
            raise e

    def _find_domain(self, domain):
        """
        Find the domain doc for a given domain.

        :param str domain: The domain for which to find the domain_id.
        :returns: The domain doc, if found.
        :rtype: obj
        :raises certbot.errors.PluginError: if no domain_id is found.
        """

        zone_name_guesses = dns_common.base_domain_name_guesses(domain)

        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.api_key 
        }
        for zone_name in zone_name_guesses:
            try:
                resp = requests.get(W4DNS_BASE_URL + "/domain?pagesize=1&q=" + zone_name, headers=headers)
            except e:
                raise errors.PluginError('Error determining domain_id for {0}'.format(domain))

            dataresp = resp.json()
            if dataresp['data'] and len(dataresp['data']) > 0:
                logger.debug('Found domain_id of %s for %s using name %s', dataresp['data'][0]['_id'], domain, zone_name)
                return {
                    '_id': dataresp['data'][0]['_id'],
                    'name': dataresp['data'][0]['name']
                }

        raise errors.PluginError('Unable to determine domain_id for {0} using zone names: {1}'.format(domain, zone_name_guesses))

    def _find_txt_record_id(self, domain_id, record_name, record_content):
        """
        Find the record_id for a TXT record with the given name and content.

        :param str domain_id: The domain_id which contains the record.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :returns: The record_id, if found.
        :rtype: str
        """
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.api_key
        }
        try:
            resp = requests.get(W4DNS_BASE_URL + "/dnsrecord/" + domain_id + "?pagesize=1&q=" + record_name, headers=headers)
        except e:
                raise errors.PluginError('Error determining record_id for {0} of domain {1}'.format(record_name, domain))

        dataresp = resp.json()
        if dataresp['data']:
            # Cleanup is returning the system to the state we found it. If, for some reason,
            # there are multiple matching records, we only delete one because we only added one.
            for record in dataresp['data']:
                if record['type'] == 'TXT' and record['content'] == record['content']:
                    return record['_id']

        raise errors.PluginError('Unable to find TXT record.')

    def _add_dns_record(self, domain_id, data):
        """
        Add a dns record to domain

        :param str domain_id: The domain_id where to add the record to
        :param obj data: The domain record data
        """
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Bearer ' + self.api_key
        }
        try:
            requests.post(W4DNS_BASE_URL + "/dnsrecord/" + domain_id, headers=headers, data=urlencode(data))
        except e:
                raise errors.PluginError('Error adding record to domain {0}'.format(domain_id))

    def _delete_dns_record(self, domain_id, record_id):
        """
        Remove a dns record from domain

        :param str domain_id: The domain_id where to remove the record from
        :param str record_id: The record_id of the record to remove
        """
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + self.api_key
        }
        try:
            requests.delete(W4DNS_BASE_URL + "/dnsrecord/" + domain_id + "/" + record_id, headers=headers)
        except e:
            raise errors.PluginError('Error removing record from domain {0}: {1}'.format(domain_id, record_id))

