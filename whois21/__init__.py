# whois21.__init__.py

import re
import os
import json
import socket

from datetime import datetime
from typing import Union, Set, Sequence

import log21
import requests
import importlib_resources

from whois21.ASN import download_asn_json, get_asn_dict, get_asn_services, ip_registration_data_lookup_, \
    ip_registration_data_lookup, validate_ip
from whois21.DNS import download_dns_json, get_dns_dict, get_dns_services, domain_registration_data_lookup_, \
    domain_registration_data_lookup
from .__main__ import main

__version__ = '1.1.1'
__github__ = 'https://github.com/MPCodeWriter21/whois21'
__author__ = 'CodeWriter21'
__email__ = 'CodeWriter21@gmail.com'
__license__ = 'Apache License 2.0'

__all__ = ['__version__', '__github__', '__author__', '__email__', '__license__', 'download_asn_json',
           'get_asn_dict', 'get_asn_services', 'ip_registration_data_lookup_', 'ip_registration_data_lookup',
           'download_dns_json', 'get_dns_dict', 'get_dns_services', 'domain_registration_data_lookup_',
           'domain_registration_data_lookup', 'validate_ip', 'WHOIS', 'registration_data_lookup', 'get_whois_servers',
           'whois_servers', 'vcard_map']

LRED = log21.get_color('Light Red')
LGREEN = log21.get_color('Light Green')
LBLUE = log21.get_color('Light Blue')
LCYAN = log21.get_color('Light Cyan')
RED = log21.get_color('Red')
GREEN = log21.get_color('Green')
BLUE = log21.get_color('Blue')
CYAN = log21.get_color('Cyan')
RESET = log21.get_color('Reset')


def download_whois_servers(path: Union[str, os.PathLike] = None) -> str:
    """
    Downloads the whois whois-servers.txt file from https://www.nirsoft.net/whois-servers.txt.

    :param path: The path to the whois file.
    :return: The path to the downloaded file.
    """
    if not path:
        path = importlib_resources.files('whois21') / 'whois-servers.txt'

    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)

    log21.debug(f'Downloading {LGREEN}whois-servers.txt{RESET} file to `{BLUE}{path}{RESET}`')

    with open(path, 'wb') as f:
        f.write(requests.get('https://www.nirsoft.net/whois-servers.txt').content)

    return str(path)


def get_whois_servers(force_download: bool = False, path: Union[str, os.PathLike] = None):
    """
    Returns a dictionary of the whois-servers.txt file.

    :param force_download: If True, the whois-servers.txt file will be downloaded again.
    :param path: The path to the whois-servers.txt file.
    :return: A dictionary of the whois-servers.txt file.
    """
    if not path:
        path = importlib_resources.files('whois21') / 'whois-servers.txt'

    if not os.path.exists(path) or force_download:
        download_whois_servers(path)

    data = dict()
    with open(path, 'r') as f:
        for line in f:
            if line.startswith(';') or not ' ' in line:
                continue
            key, value = line.split(' ', 1)
            data[key] = value.strip(' \n')

    return data


whois_servers: dict = {
    'ABUSE_HOST': 'whois.abuse.net',
    'LNICHOST': 'whois.lacnic.net',  # Types of queries: POCs, ownerid, CIDR blocks, IP and AS numbers.
    'ai': {'whois.nic.ai'},
    'app': {'whois.nic.google'},
    'ar': {'whois.nic.ar'},
    'by': {'whois.cctld.by'},
    'ca': {'whois.ca.fury.ca'},
    'chat': {'whois.nic.chat'},
    'cl': {'whois.nic.cl'},
    'com': {'whois.crsnic.net', 'WHOIS.ENOM.COM', 'whois.joker.com', 'whois.corporatedomains.com',
            'whois.verisign-grs.com'},
    'cr': {'whois.nic.cr'},
    'edu': {'whois.crsnic.net', 'whois.educause.net'},
    'de': {'whois.denic.de'},
    'dev': {'whois.nic.google'},
    'do': {'whois.nic.do'},
    'games': {'whois.nic.games'},
    'gov': {'whois.nic.gov'},
    'goog': {'whois.nic.google'},
    'google': {'whois.nic.google'},
    'group': {'whois.namecheap.com'},
    'hk': {'whois.hkirc.hk'},
    'hn': {'whois.nic.hn'},
    'hr': {'whois.dns.hr'},
    'id': {'whois.pandi.or.id'},
    'ist': {'whois.afilias-srs.net'},
    'jobs': {'whois.nic.jobs'},
    'jp': {'whois.jprs.jp'},
    'kz': {'whois.nic.kz'},
    'lat': {'whois.nic.lat'},
    'li': {'whois.nic.li'},
    'lt': {'whois.domreg.lt'},
    'market': {'whois.nic.market'},
    'money': {'whois.nic.money'},
    'mx': {'whois.mx'},
    'net': {'whois.crsnic.net'},
    'nl': {'whois.domain-registry.nl'},
    'online': {'whois.nic.online'},
    'ooo': {'whois.nic.ooo'},
    'org': {'whois.publicdomainregistry.com', 'whois.gandi.net', 'whois.markmonitor.com'},
    'page': {'whois.nic.page'},
    'pe': {'kero.yachay.pe'},
    'website': {'whois.nic.website'},
    'za': {'whois.registry.net.za'}
}

for _key, _value in get_whois_servers().items():
    whois_servers[_key] = {*whois_servers.get(_key, {}), _value}

with open(str(importlib_resources.files('whois21') / 'vcard-map.json'), 'r') as f:
    vcard_map = json.load(f)


class WHOIS:
    __domain: str
    __success: bool = False
    __error: str = ''
    __raw: bytes = b''
    __servers: Set[str] = set()
    __whois_data: dict = {}
    __rdap_data: dict = {}
    timeout: int = 10

    def __init__(self, domain: str, servers: Sequence[str] = None, timeout: int = 10, use_rdap: bool = True,
                 force_rdap: bool = False):
        self.whois(domain, servers, timeout, use_rdap, force_rdap)

    def whois(self, domain: str, servers: Sequence[str] = None, timeout: int = 10, use_rdap: bool = True,
              force_rdap: bool = False):
        """
        Queries the whois server for the domain.

        :param domain: The domain/ip to query.
        :param servers: The servers to use.
        :param timeout: The timeout in seconds.
        :param use_rdap: If True, the RDAP server will be used if the whois servers don't respond.
        :param force_rdap: If True, the RDAP server will be used even if the whois servers respond.
        """
        self.__domain = domain.lower()
        self.__success = False
        self.__servers = set(servers) if servers else set()
        self.__whois_data = {}
        self.timeout = timeout
        self.__error = ''
        self.__raw = b''

        if not force_rdap:
            self.__whois()

        if (not self.__success and use_rdap) or force_rdap:
            self.__rdap()

        self.__set_attrs()

    def __set_attrs(self):
        # Save the whois information in object attributes.
        self.registry_domain_id = self.__whois_data.get('REGISTRY DOMAIN ID', '')
        self.registrar_whois_server = self.__whois_data.get('REGISTRAR WHOIS SERVER', '')
        self.registrar_url = self.__whois_data.get('REGISTRAR URL', '')
        self.updated_date = self.__whois_data.get('UPDATED DATE', '')
        self.creation_date = self.__whois_data.get('CREATION DATE', '')
        self.expires_date = self.__whois_data.get('REGISTRY EXPIRY DATE', '') or \
                            self.__whois_data.get('REGISTRAR REGISTRATION EXPIRATION DATE', '')
        self.registrar_name = self.__whois_data.get('REGISTRAR', '')
        self.registrar_iana_id = self.__whois_data.get('REGISTRAR IANA ID', '')
        self.registrar_abuse_contact_email = self.__whois_data.get('REGISTRAR ABUSE CONTACT EMAIL', '')
        self.registrar_abuse_contact_phone = self.__whois_data.get('REGISTRAR ABUSE CONTACT PHONE', '')
        self.status = self.__whois_data.get('DOMAIN STATUS', [])
        self.name_servers = self.__whois_data.get('NAME SERVER', [])

        def parse_time(date_time: str) -> Union[datetime, None]:
            """
            Parses a date time string.

            :param date_time: The date time string.
            :return: The parsed date time.
            """
            result = re.findall(r'(\d{4}\-\d{2}\-\d{2}).(\d{2}:\d{2}:\d{2})*', date_time)
            if result:
                return datetime.strptime(' '.join(result[0]), '%Y-%m-%d %H:%M:%S')
            return None

        # Convert the dates to datetime objects.
        if self.updated_date:
            self.updated_date = parse_time(self.updated_date)
        if self.creation_date:
            self.creation_date = parse_time(self.creation_date)
        if self.expires_date:
            self.expires_date = parse_time(self.expires_date)

    def __whois(self):
        if not self.__servers:
            # Collects a set of whois servers to use.
            self.__whois_iana()
            self.__get_whois_server_for_tld()

        if not self.__servers:
            self.__error = 'No whois servers found.'
            log21.debug('No whois servers found.')
            return

        log21.debug(f'WHOIS servers: {GREEN}{log21.pformat(self.__servers)}{RESET}')

        self.__call_whois_servers()

        if self.__error:
            return

        self.__success = True
        self.__error = ''
        log21.debug(f'{LGREEN}WHOIS data successfully parsed.{RESET}')

    def __whois_iana(self):
        # Send a query to the whois.iana.org server to find the whois server for the domain.
        # Create a socket connection to the whois.iana.org server.
        log21.debug(f'Connecting to {LBLUE}whois.iana.org:43{RESET}...')
        try:
            sock = socket.create_connection(('whois.iana.org', 43))
            sock.settimeout(self.timeout)
        except socket.error as e:
            log21.debug(f'Error connecting to "{RED}whois.iana.org:43{RESET}": '
                        f'{LRED}{e.__class__.__name__}: {e}{RESET}')
            self.__error = f'Error connecting "to whois.iana.org:43": {e.__class__.__name__}: {e}'
            return
        # Send the domain name to the whois.iana.org server.
        log21.debug(f'Sending query for {LCYAN}{self.domain}{RESET}...')
        try:
            sock.send(self.domain.encode('utf-8') + b'\r\n')
        except socket.error as e:
            log21.debug(f'Error sending query to "{RED}whois.iana.org:43{RESET}": '
                        f'{LRED}{e.__class__.__name__}: {e}{RESET}')
            self.__error = f'Error sending query to "whois.iana.org:43": {e.__class__.__name__}: {e}'
            return
        # Receive the raw data from the whois.iana.org server.
        self.__raw = b''
        log21.debug('Receiving data...')
        try:
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                self.__raw += data
        except socket.error as e:
            log21.debug(f'Error receiving data from "{RED}whois.iana.org:43{RESET}": '
                        f'{LRED}{e.__class__.__name__}: {e}{RESET}')
            self.__error = f'Error receiving data from "whois.iana.org:43": {e.__class__.__name__}: {e}'
            return
        sock.close()

        # Checks if we received any data from the whois.iana.org server.
        if not self.__raw:
            log21.debug(f'{LRED}No data received.{RESET}')
            self.__error = 'No data received from whois.iana.org.'
            return

        log21.debug('Parsing data: Searching for whois server...')
        # Parse the raw data from the whois.iana.org server and extract the whois server.
        for line in self.__raw.decode('utf-8').split('\n'):
            if line.startswith('whois:'):
                self.__servers.add(line[6:].strip())
                break
        else:
            log21.debug(f'{LRED}No whois server found.{RESET}')
            self.__error = 'No whois server found.'
            log21.debug('Trying to get another whois server...')
            self.__get_whois_server_for_tld()
            self.__error = ''

    def __get_whois_server_for_tld(self):
        tld = self.domain.split('.')[-1]
        if tld.isdigit():
            self.__whois_server = 'whois.arin.net'
            if validate_ip(self.domain):
                self.__servers.add(whois_servers['LNICHOST'])
        else:
            if tld in whois_servers:
                self.__servers.update(whois_servers[tld])

            self.__servers.add(tld + '.whois-servers.net')
            self.__servers.add('whois.nic.' + tld)

    def __call_whois_servers(self):
        # Get the whois information for the domain.
        for whois_server in self.__servers:
            # Create a socket connection to the whois server.
            log21.debug(f'Connecting to {LBLUE}{whois_server}{RESET}...')
            try:
                sock = socket.create_connection((whois_server, 43))
                sock.settimeout(self.timeout)
            except socket.error as e:
                log21.debug(f'Error connecting to "{RED}{whois_server}{RESET}": '
                            f'{LRED}{e.__class__.__name__}: {e}{RESET}')
                self.__error = f'Error connecting to "{whois_server}": {e.__class__.__name__}: {e}'
                continue
            # Send the domain name to the whois server.
            log21.debug(f'Sending query for {LCYAN}{self.domain}{RESET}...')
            try:
                sock.send(self.domain.encode('utf-8') + b'\r\n')
            except socket.error as e:
                log21.debug(f'Error sending query to "{RED}{whois_server}{RESET}": '
                            f'{LRED}{e.__class__.__name__}: {e}{RESET}')
                self.__error = f'Error sending query to "{whois_server}": {e.__class__.__name__}: {e}'
                continue
            # Receive the raw whois data from the whois server.
            self.__raw = b''
            log21.debug('Receiving data...')
            try:
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    self.__raw += data
            except socket.error as e:
                log21.debug(f'Error receiving data from "{RED}{whois_server}{RESET}": '
                            f'{LRED}{e.__class__.__name__}: {e}{RESET}')
                self.__error = f'Error receiving data from "{whois_server}": {e.__class__.__name__}: {e}'
                continue
            sock.close()

            # Checks if we received any data from the whois server.
            if not self.__raw:
                log21.debug(f'No data received from {RED}{whois_server}{RESET}.')
                self.__error = f'No data received from {whois_server}.'
                continue
            # Parse the raw whois data from the whois server and extract the whois information.
            log21.debug('Parsing data...')
            self.__whois_data = {}
            i = 0
            lines = self.__raw.decode('utf-8').split('\n')
            while i < len(lines):
                line = lines[i]
                if line.startswith('%') or line.startswith('#'):
                    i += 1
                    continue
                if ':' in line:
                    key, value = line.split(':', 1)
                    if not value:
                        value = ''
                        for j in range(i + 1, len(lines)):
                            if lines[j].startswith('%') or lines[j].startswith('#'):
                                continue
                            if ':' in lines[j]:
                                break
                            value += lines[j].strip() + '\n'
                            i = j
                    if key.strip().upper() not in self.__whois_data:
                        self.__whois_data[key.strip().upper()] = value.strip()
                    else:
                        if isinstance(self.__whois_data[key.strip().upper()], list):
                            self.__whois_data[key.strip().upper()].append(value.strip())
                        elif isinstance(self.__whois_data[key.strip().upper()], str):
                            self.__whois_data[key.strip().upper()] = [self.__whois_data[key.strip().upper()],
                                                                      value.strip()]
                i += 1

            if not self.__whois_data:
                log21.debug(f'{LRED}No data found.{RESET}')
                self.__error = 'No whois data found.'
                continue

            # Check if the whois server returned any error messages.
            if 'ERROR' in self.__whois_data or 'WHOIS ERROR' in self.__whois_data:
                log21.debug(f'{LRED}Error{RESET} found in whois data.')
                self.__error = 'Error found in whois data.'
                continue

            self.__error = ''
            return

    def __rdap(self):
        # Get the rdap information for the domain.
        log21.debug('Getting rdap information...')
        try:
            self.__rdap_data = registration_data_lookup(self.domain)
        except Exception as e:
            log21.debug(f'{LRED}Error{RESET} getting rdap information: {e.__class__.__name__}: {e}')
            self.__error = f'Error getting rdap information: {e.__class__.__name__}: {e}'
            return

        if not self.__rdap_data:
            log21.debug(f'{LRED}No data found.{RESET}')
            self.__error = 'No rdap data found.'
            return

        # Check if the rdap server returned any error messages.
        if 'error' in self.__rdap_data:
            log21.debug(f'{LRED}Error{RESET} found in rdap data.')
            self.__error = 'Error found in rdap data.'
            return

        self.__parse_rdap_data()
        return

    def __parse_rdap_data(self):
        """
        Parses the RDAP data and puts some information in whois_data dictionary.
        """

        # Parse the rdap data and extract the whois information.
        log21.debug('Parsing rdap data...')
        self.__whois_data = {
            'REGISTRAR WHOIS SERVER': self.__rdap_data.get('port43'),
            'REGISTRY DOMAIN ID': self.__rdap_data.get('handle')
        }
        # Handle events
        for event in self.__rdap_data.get('events', []):
            if event.get('eventAction') == 'transfer':
                self.__whois_data['TRANSFER DATE'] = event.get('eventDate')
            elif event.get('eventAction') == 'expiration':
                self.__whois_data['REGISTRY EXPIRY DATE'] = event.get('eventDate')
            elif event.get('eventAction') == 'registration':
                self.__whois_data['CREATION DATE'] = event.get('eventDate')
            elif event.get('eventAction') == 'last changed':
                self.__whois_data['UPDATED DATE'] = event.get('eventDate')

        # Handle status
        self.__whois_data['DOMAIN STATUS'] = self.__rdap_data.get('status', [])

        self.__whois_data['NAME SERVER'] = []
        # Handle nameservers
        for nameserver in self.__rdap_data.get('nameservers', []):
            if nameserver.get('ldhName'):
                self.__whois_data['NAME SERVER'].append(nameserver.get('ldhName'))

        # Handle entities
        def handle_entity(prefix: str, entity_: dict):
            """
            Handles an entity dictionary.
            Example entity:
            >>> {
            ...     "objectClassName": "entity",
            ...     "handle": "...",
            ...     "roles": ["..."],
            ...     "publicIds": [{...}],
            ...     "vcardArray": ["vcard", [...]],
            ...     "entities": [{...}, ...],
            ...     "events": [{...}, ...],
            ...     "remarks": [{...}, ...]
            ... }
            ...

            :param prefix: The prefix to use for the key.
            :param entity_: The entity dictionary.
            """
            prefix += entity_.get('roles', [''])[0]
            prefix = prefix.strip().upper()
            for public_id in entity_.get('publicIds', []):
                # Example:
                # "publicIds": [
                #     {
                #         "type": "IANA Registrar ID",
                #         "identifier": "292"
                #     }
                # ]
                if 'type' in public_id and 'identifier' in public_id:
                    self.__whois_data[public_id.get('type').upper()] = public_id.get('identifier')

            # Handle vcards
            # Reference: https://www.rfc-editor.org/rfc/rfc6350.txt
            # Reference: https://en.wikipedia.org/wiki/VCard
            # vcardArray Example:
            # "vcardArray": [
            #                   "vcard",
            #                   [
            #                       [
            #                           "version",
            #                           {},
            #                           "text",
            #                           "4.0"
            #                       ],
            #                       [
            #                           "fn",
            #                           {},
            #                           "text",
            #                           "MarkMonitor Inc."
            #                       ]
            #                   ]
            #               ]
            for vcard in entity_.get('vcardArray', ['vcard', []])[1]:
                data = vcard[3]
                temp = []
                if isinstance(data, list):
                    for part in data:
                        if part:
                            temp.append(part)
                data = ' '.join(temp)

                if vcard[0] in vcard_map:
                    self.__whois_data[prefix + ' ' + vcard_map[vcard[0]]] = data
                elif vcard[0] != 'version':
                    self.__whois_data[prefix + ' ' + vcard[0].upper()] = data

            for _entity in entity_.get('entities', []):
                handle_entity(prefix, _entity)

        for entity in self.__rdap_data.get('entities', []):
            handle_entity('', entity)

    @property
    def whois_data(self):
        return self.__whois_data

    @property
    def rdap_data(self):
        return self.__rdap_data

    @property
    def servers(self):
        return self.__servers

    @property
    def raw(self):
        return self.__raw

    @property
    def domain(self):
        return self.__domain

    @property
    def success(self):
        return self.__success

    @property
    def error(self):
        return self.__error

    def __str__(self):
        return self.__raw.decode('utf-8')

    def __repr__(self):
        return f'WHOIS(domain="{self.__domain}", success={self.__success})'

    def get(self, key: str, default=None):
        return self.__whois_data.get(key.upper(), default)

    def __getitem__(self, key: str):
        return self.__whois_data[key.upper()]


def registration_data_lookup(domain: str, timeout: int = 10) -> dict:
    """
    Lookup the registration data for a domain/ip.
    :param domain: The domain/ip to lookup.
    :param timeout: The timeout for the socket connection.
    :return: A WHOIS object.
    """
    if validate_ip(domain):
        return ip_registration_data_lookup(domain, timeout)
    else:
        return domain_registration_data_lookup(domain, timeout)
