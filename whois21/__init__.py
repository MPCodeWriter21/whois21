# whois21.__init__.py

import os
import json
import socket
import string
from typing import Any, Set, Dict, Tuple, Union, Optional, Sequence
from datetime import datetime

import log21
import chardet
import requests
import importlib_resources
from log21.Colors import (RED, BLUE, GREEN, RESET, LIGHT_RED as LRED,
                          LIGHT_BLUE as LBLUE, LIGHT_CYAN as LCYAN,
                          LIGHT_GREEN as LGREEN)

from whois21.IP import (validate_ip, get_ipv4_services, get_ipv6_services,
                        download_ipv4_json, download_ipv6_json,
                        ip_registration_data_lookup, ip_registration_data_lookup_)
from whois21.API import lookup_ip_ip_api, batch_lookup_ip_ip_api
from whois21.ASN import (get_asn_dict, validate_asn, get_asn_services,
                         download_asn_json, asn_registration_data_lookup,
                         asn_registration_data_lookup_)
from whois21.DNS import (get_dns_dict, get_dns_services, download_dns_json,
                         domain_registration_data_lookup,
                         domain_registration_data_lookup_)

__version__ = '1.4.2'
__github__ = 'https://github.com/MPCodeWriter21/whois21'
__author__ = 'CodeWriter21'
__email__ = 'CodeWriter21@gmail.com'
__license__ = 'Apache License 2.0'

__all__ = [
    '__version__', '__github__', '__author__', '__email__', '__license__',
    'validate_asn', 'download_asn_json', 'get_asn_dict', 'get_asn_services',
    'asn_registration_data_lookup_', 'asn_registration_data_lookup',
    'download_ipv4_json', 'download_ipv6_json', 'get_ipv4_services',
    'get_ipv6_services', 'ip_registration_data_lookup_', 'ip_registration_data_lookup',
    'download_dns_json', 'get_dns_dict', 'get_dns_services',
    'domain_registration_data_lookup_', 'domain_registration_data_lookup',
    'validate_ip', 'WHOIS', 'registration_data_lookup', 'get_whois_servers',
    'whois_servers', 'vcard_map', 'lookup_ip_ip_api', 'batch_lookup_ip_ip_api'
]

STRIP_CHARS = string.whitespace + '<>'


def download_whois_servers(
    *, path: Optional[Union[str, os.PathLike]] = None, timeout: int = 10
) -> str:
    """Downloads the whois whois-servers.txt file from
    https://www.nirsoft.net/whois-servers.txt.

    :param path: The path to the whois file.
    :param timeout: The timeout for the request.
    :return: The path to the downloaded file.
    """
    if not path:
        path = str(importlib_resources.files('whois21') / 'whois-servers.txt')

    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)

    log21.debug(
        f'Downloading {LGREEN}whois-servers.txt{RESET} file to `{BLUE}{path}{RESET}`'
    )

    with open(path, 'wb') as file:
        file.write(
            requests.get('https://www.nirsoft.net/whois-servers.txt',
                         timeout=timeout).content
        )

    return str(path)


def get_whois_servers(
    *, force_download: bool = False, path: Optional[Union[str, os.PathLike]] = None
):
    """Returns a dictionary of the whois-servers.txt file.

    :param force_download: If True, the whois-servers.txt file will be downloaded again.
    :param path: The path to the whois-servers.txt file.
    :return: A dictionary of the whois-servers.txt file.
    """
    if not path:
        path = str(importlib_resources.files('whois21') / 'whois-servers.txt')

    if not os.path.exists(path) or force_download:
        download_whois_servers(path=path)

    if os.stat(path).st_size == 0:
        download_whois_servers(path=path)

    data = {}
    with open(path, 'r', encoding='utf-8') as file:
        for line in file:
            if line.startswith(';') or ' ' not in line:
                continue
            key, value = line.split(' ', 1)
            data[key] = value.strip(' \n')

    return data


whois_servers: dict = {
    'ABUSE_HOST': 'whois.abuse.net',
    # Types of queries: POCs, ownerid, CIDR blocks, IP and AS numbers.
    'LNICHOST': 'whois.lacnic.net',
    'ai': {'whois.nic.ai'},
    'app': {'whois.nic.google'},
    'ar': {'whois.nic.ar'},
    'by': {'whois.cctld.by'},
    'ca': {'whois.ca.fury.ca'},
    'chat': {'whois.nic.chat'},
    'cl': {'whois.nic.cl'},
    'com': {
        'whois.crsnic.net', 'WHOIS.ENOM.COM', 'whois.joker.com',
        'whois.corporatedomains.com', 'whois.verisign-grs.com'
    },
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
    'org':
    {'whois.publicdomainregistry.com', 'whois.gandi.net', 'whois.markmonitor.com'},
    'page': {'whois.nic.page'},
    'pe': {'kero.yachay.pe'},
    'website': {'whois.nic.website'},
    'za': {'whois.registry.net.za'}
}

for _key, _value in get_whois_servers().items():
    whois_servers[_key] = {*whois_servers.get(_key, {}), _value}

with open(str(importlib_resources.files('whois21') / 'vcard-map.json'), 'r',
          encoding='utf-8') as f:
    vcard_map = json.load(f)


class WHOIS:  # pylint: disable=too-many-instance-attributes
    """WHOIS client."""
    __domain: str
    __success: bool = False
    __error: Optional[Tuple[str, Optional[Exception]]] = None
    __raw: bytes = b''
    __servers: Set[str] = set()
    __whois_data: dict = {}
    __rdap_data: dict = {}
    __encode_encoding: str = 'utf-8'
    __decode_encoding: Optional[str] = None
    __encoding_errors: str = 'strict'
    timeout: int = 10

    def __init__(
        self,
        domain: str,
        *,
        servers: Optional[Sequence[str]] = None,
        timeout: int = 10,
        use_rdap: bool = True,
        force_rdap: bool = False,
        run_whois: bool = True,
        encode_encoding: str = 'utf-8',
        decode_encoding: Optional[str] = None,
        encoding_errors: str = 'strict',
    ):
        """Initialize WHOIS object.

        :param domain: Domain name/IP to query.
        :param servers: List of WHOIS servers to use.
        :param timeout: Timeout in seconds. (default: 10)
        :param use_rdap: Use RDAP if available and WHOIS fails.
        :param force_rdap: Force RDAP usage.
        :param run_whois: Run WHOIS query. (default: True)
        :param encode_encoding: Encoding to use for encoding. (default: utf-8)
        :param decode_encoding: Encoding to use for decoding. (default: AUTODETECT)
        :param encoding_errors: Encoding error handling. (default: strict)
        """
        self.registry_domain_id = None
        self.registrar_whois_server = None
        self.registrar_url = None
        self.updated_date: Optional[datetime] = None
        self.creation_date: Optional[datetime] = None
        self.expires_date: Optional[datetime] = None
        self.registrar_name: Union[str, set] = ''
        self.registrar_iana_id = None
        self.registrar_abuse_contact_email = None
        self.registrar_abuse_contact_phone = None
        self.emails: set = set()
        self.phone_numbers: set = set()
        self.fax_numbers: set = set()
        self.status = None
        self.name_servers = None
        self.__domain = domain.lower() if domain else self.__domain
        self.__success = False
        self.__servers = set(servers) if servers else set()
        self.__whois_data = {}
        self.timeout = timeout
        self.__error = None
        self.__raw = b''
        self.__encode_encoding = encode_encoding
        self.__decode_encoding = decode_encoding
        self.__encoding_errors = encoding_errors

        if run_whois:
            self.whois(
                domain,
                servers=servers,
                timeout=timeout,
                use_rdap=use_rdap,
                force_rdap=force_rdap,
                encode_encoding=encode_encoding,
                decode_encoding=decode_encoding,
                encoding_errors=encoding_errors,
            )

    def whois(
        self,
        domain: Optional[str] = None,
        *,
        servers: Optional[Sequence[str]] = None,
        timeout: int = 10,
        use_rdap: bool = True,
        force_rdap: bool = False,
        encode_encoding: str = 'utf-8',
        decode_encoding: Optional[str] = None,
        encoding_errors: str = 'strict',
    ):
        """Queries the whois server for the domain.

        :param domain: The domain/ip to query.
        :param servers: The servers to use.
        :param timeout: The timeout in seconds.
        :param use_rdap: If True, the RDAP server will be used if the whois servers
            don't respond.
        :param force_rdap: If True, the RDAP server will be used even if the whois
            servers respond.
        :param encode_encoding: Encoding to use for encoding. (default: utf-8)
        :param decode_encoding: Encoding to use for decoding. (default: AUTODETECT)
        :param encoding_errors: How to handle encoding errors. (default: strict)
        """
        self.__domain = domain.lower() if domain else self.__domain
        self.__success = False
        self.__servers = set(servers) if servers else set()
        self.__whois_data = {}
        self.timeout = timeout
        self.__error = None
        self.__raw = b''
        self.__encode_encoding = encode_encoding
        self.__decode_encoding = decode_encoding
        self.__encoding_errors = encoding_errors

        if not force_rdap:
            self.__whois()

        if (not self.__success and use_rdap) or force_rdap:
            self.__rdap()

        self.__set_attrs()

    def __set_attrs(self):
        data = self.__whois_data

        # Save the whois information in object attributes.
        self.registry_domain_id = data.get('REGISTRY DOMAIN ID', '')
        self.registrar_whois_server = data.get('REGISTRAR WHOIS SERVER', '')
        self.registrar_url = data.get('REGISTRAR URL', '')
        self.registrar_name = data.get('REGISTRAR', '')
        if isinstance(self.registrar_name, list):
            self.registrar_name = set(self.registrar_name)
        self.registrar_iana_id = data.get('REGISTRAR IANA ID', '')
        self.registrar_abuse_contact_email = data.get(
            'REGISTRAR ABUSE CONTACT EMAIL', ''
        )
        self.registrar_abuse_contact_phone = data.get(
            'REGISTRAR ABUSE CONTACT PHONE', ''
        )
        mails = []
        emails = (
            ([mails] if isinstance(mails := data.get('EMAIL', []), str) else mails) +
            ([mails] if isinstance(mails := data.get('E-MAIL', []), str) else mails)
        )
        if isinstance(emails, list):
            self.emails = set(emails)
        phone_numbers = data.get('PHONE', [])
        if isinstance(phone_numbers, str):
            self.phone_numbers = {phone_numbers}
        if isinstance(phone_numbers, list):
            self.phone_numbers = set(phone_numbers)
        fax = []
        fax_numbers = (
            ([fax] if isinstance(fax := data.get('FAX', []), str) else fax) +
            ([fax] if isinstance(fax := data.get('FAX-NO', []), str) else fax)
        )
        if isinstance(fax_numbers, list):
            self.fax_numbers = set(fax_numbers)
        self.status = data.get('DOMAIN STATUS', [])
        self.name_servers = data.get('NAME SERVER', []) + data.get('NSERVER', [])

        def parse_time(date_time: str) -> Union[datetime, None]:
            """Parses a date time string.

            :param date_time: The date time string.
            :return: The parsed date time.
            """
            try:
                return datetime.fromisoformat(date_time)
            except ValueError:
                return None

        # Convert the dates to datetime objects.
        updated_date = (
            data.get('UPDATED DATE', '') or data.get('UPDATED', '')
            or data.get('LAST UPDATED', '')
        )
        creation_date = (
            data.get('CREATION DATE', '') or data.get('CREATED DATE', '')
            or data.get('CREATED', '')
        )
        expires_date = (
            data.get('REGISTRY EXPIRY DATE', '') or data.get('EXPIRY DATE', '')
            or data.get('REGISTRAR REGISTRATION EXPIRATION DATE', '')
        )
        if updated_date:
            self.updated_date = parse_time(updated_date)
        if creation_date:
            self.creation_date = parse_time(creation_date)
        if expires_date:
            self.expires_date = parse_time(expires_date)

    def __whois(self):
        if not self.__servers:
            # Collects a set of whois servers to use.
            self.__whois_iana()
            self.__get_whois_server_for_tld()

        if not self.__servers:
            self.__error = ('No whois servers found.', None)
            log21.debug('No whois servers found.')
            return

        log21.debug(f'WHOIS servers: {GREEN}{log21.pformat(self.__servers)}{RESET}')

        self.__call_whois_servers()

        if self.__error:
            return

        self.__success = True
        self.__error = None
        log21.debug(f'{LGREEN}WHOIS data successfully parsed.{RESET}')

    def __whois_iana(self):
        # Send a query to the whois.iana.org server to find the whois server for the
        # domain.
        # Create a socket connection to the whois.iana.org server.
        log21.debug(f'Connecting to {LBLUE}whois.iana.org:43{RESET}...')
        try:
            sock = socket.create_connection(('whois.iana.org', 43))
            sock.settimeout(self.timeout)
        except socket.error as ex:
            log21.debug(
                f'Error connecting to "{RED}whois.iana.org:43{RESET}": '
                f'{LRED}{ex.__class__.__name__}: {ex}{RESET}'
            )
            self.__error = (
                'Error connecting "to whois.iana.org:43": '
                f'{ex.__class__.__name__}: {ex}', ex
            )
            return
        # Send the domain name to the whois.iana.org server.
        log21.debug(f'Sending query for {LCYAN}{self.domain}{RESET}...')
        try:
            sock.send(
                str(self.domain
                    ).encode(self.__encode_encoding, errors=self.__encoding_errors) +
                b'\r\n'
            )
        except socket.error as ex:
            log21.debug(
                f'Error sending query to "{RED}whois.iana.org:43{RESET}": '
                f'{LRED}{ex.__class__.__name__}: {ex}{RESET}'
            )
            self.__error = (
                'Error sending query to "whois.iana.org:43": '
                f'{ex.__class__.__name__}: {ex}', ex
            )
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
        except socket.error as ex:
            log21.debug(
                f'Error receiving data from "{RED}whois.iana.org:43{RESET}": '
                f'{LRED}{ex.__class__.__name__}: {ex}{RESET}'
            )
            self.__error = (
                'Error receiving data from "whois.iana.org:43": '
                f'{ex.__class__.__name__}: {ex}', ex
            )
            return
        sock.close()

        # Checks if we received any data from the whois.iana.org server.
        if not self.__raw:
            log21.debug(f'{LRED}No data received.{RESET}')
            self.__error = ('No data received from whois.iana.org.', None)
            return

        log21.debug('Parsing data: Searching for whois server...')
        # Parse the raw data from the whois.iana.org server and extract the whois
        # server.
        for line in self.__raw.decode(self.__get_decode_encoding(self.__raw),
                                      errors=self.__encoding_errors).split('\n'):
            if line.startswith('whois:'):
                self.__servers.add(line[6:].strip())
                break
        else:
            log21.debug(f'{LRED}No whois server found.{RESET}')
            self.__error = ('No whois server found.', None)
            log21.debug('Trying to get another whois server...')
            self.__get_whois_server_for_tld()
            self.__error = None

    def __get_whois_server_for_tld(self):
        if isinstance(self.domain, int):
            self.__servers.update((whois_servers['LNICHOST'], 'whois.arin.net'))
            return
        tld = str(self.domain).rsplit('.', maxsplit=1)[-1]
        if tld.isdigit():
            if validate_ip(self.domain):
                self.__servers.update((whois_servers['LNICHOST'], 'whois.arin.net'))
        else:
            if tld in whois_servers:
                self.__servers.update(whois_servers[tld])

            self.__servers.add(tld + '.whois-servers.net')
            self.__servers.add('whois.nic.' + tld)

    # pylint: disable=too-many-branches, too-many-statements, too-many-nested-blocks
    def __call_whois_servers(self):
        # Get the whois information for the domain.
        for whois_server in self.__servers:
            if self.__call_whois_server(whois_server):
                break

    def __call_whois_server(self, whois_server: str) -> bool:
        """Call the whois server.

        :param whois_server: The whois server to call.
        :return: True if the data was received and parsed successfully, False otherwise.
        """
        # Create a socket connection to the whois server.
        log21.debug(f'Connecting to {LBLUE}{whois_server}{RESET}...')
        try:
            sock = socket.create_connection((whois_server, 43))
            sock.settimeout(self.timeout)
        except socket.error as ex:
            log21.debug(
                f'Error connecting to "{RED}{whois_server}{RESET}": '
                f'{LRED}{ex.__class__.__name__}: {ex}{RESET}'
            )
            self.__error = (
                f'Error connecting to "{whois_server}": '
                f'{ex.__class__.__name__}: {ex}', ex
            )
            return False
        # Send the domain name to the whois server.
        log21.debug(f'Sending query for {LCYAN}{self.domain}{RESET}...')
        try:
            sock.send(
                str(self.domain
                    ).encode(self.__encode_encoding, errors=self.__encoding_errors) +
                b'\r\n'
            )
        except socket.error as ex:
            log21.debug(
                f'Error sending query to "{RED}{whois_server}{RESET}": '
                f'{LRED}{ex.__class__.__name__}: {ex}{RESET}'
            )
            self.__error = (
                f'Error sending query to "{whois_server}": '
                f'{ex.__class__.__name__}: {ex}', ex
            )
            return False
        # Receive the raw whois data from the whois server.
        self.__raw = b''
        log21.debug('Receiving data...')
        try:
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                self.__raw += data
        except socket.error as ex:
            log21.debug(
                f'Error receiving data from "{RED}{whois_server}{RESET}": '
                f'{LRED}{ex.__class__.__name__}: {ex}{RESET}'
            )
            self.__error = (
                f'Error receiving data from "{whois_server}": '
                f'{ex.__class__.__name__}: {ex}', ex
            )
            return False
        sock.close()

        # Checks if we received any data from the whois server.
        if not self.__raw:
            log21.debug(f'No data received from {RED}{whois_server}{RESET}.')
            self.__error = (f'No data received from {whois_server}.', None)
            return False

        # Parse the raw whois data from the whois server and extract the whois
        # information.
        return self.__parse_whois_data()

    def __parse_whois_data(self):
        """Parse the raw whois data.

        :return: True if the data was parsed successfully, False otherwise.
        """
        log21.debug('Parsing data...')
        data = self.__whois_data = {}
        i = 0
        lines = self.__raw.decode(
            self.__get_decode_encoding(self.__raw), errors=self.__encoding_errors
        ).split('\n')
        while i < len(lines):
            line = lines[i]
            if line.startswith('%') or line.startswith('#'):
                i += 1
                continue
            if ':' in line:
                key_name, value = line.split(':', 1)
                if not value:
                    value = ''
                    for j in range(i + 1, len(lines)):
                        if lines[j].startswith('%') or lines[j].startswith('#'):
                            continue
                        if ':' in lines[j]:
                            break
                        value += lines[j].strip(STRIP_CHARS) + '\n'
                        i = j
                if (key := key_name.strip(STRIP_CHARS).upper()) not in data:
                    data[key] = value.strip(STRIP_CHARS)
                else:
                    if isinstance(data[key], list):
                        data[key].append(value.strip(STRIP_CHARS))
                    elif isinstance(data[key], str):
                        data[key] = [data[key], value.strip(STRIP_CHARS)]
            i += 1

        if not data:
            log21.debug(f'{LRED}No data found.')
            self.__error = ('No whois data found.', None)
            return False

        # Check if the whois server returned any error messages.
        if 'ERROR' in data or 'WHOIS ERROR' in data:
            log21.debug(f'{LRED}Error{RESET} found in whois data.')
            self.__error = ('Error found in whois data.', None)
            return False

        self.__error = None
        return True

    def __rdap(self):
        # Get the rdap information for the domain.
        log21.debug('Getting rdap information...')
        try:
            self.__rdap_data = registration_data_lookup(self.domain)
        except Exception as ex:  # pylint: disable=broad-except
            log21.debug(
                f'{LRED}Error{RESET} getting rdap information: '
                f'{ex.__class__.__name__}: {ex}'
            )
            self.__error = (
                'Error getting rdap information: '
                f'{ex.__class__.__name__}: {ex}', ex
            )
            return

        if not self.__rdap_data:
            log21.debug(f'{LRED}No data found.{RESET}')
            self.__error = ('No rdap data found.', None)
            return

        # Check if the rdap server returned any error messages.
        if 'error' in self.__rdap_data:
            log21.debug(f'{LRED}Error{RESET} found in rdap data.')
            self.__error = ('Error found in rdap data.', None)
            return

        self.__parse_rdap_data()
        return

    # Handle entities
    def __handle_entity(self, prefix: str, entity_: dict):
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
                self.__whois_data[public_id.get('type').upper()
                                  ] = public_id.get('identifier')

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
                        temp.append(str(part))
            data = ' '.join(temp)

            if vcard[0] in vcard_map:
                self.__whois_data[prefix + ' ' + vcard_map[vcard[0]]] = data
            elif vcard[0] != 'version':
                self.__whois_data[prefix + ' ' + vcard[0].upper()] = data

        for _entity in entity_.get('entities', []):
            self.__handle_entity(prefix, _entity)

    def __parse_rdap_data(self):
        """Parses the RDAP data and puts some information in whois_data dictionary."""

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

        for entity in self.__rdap_data.get('entities', []):
            self.__handle_entity('', entity)

        self.__success = True

    def __get_decode_encoding(self, data) -> str:
        if self.__decode_encoding:
            return self.__decode_encoding
        encoding = chardet.detect(data)['encoding']
        return encoding if encoding else 'utf-8'

    @property
    def whois_data(self) -> Dict[str, Any]:
        """A dictionary containing the parsed WHOIS data."""
        return self.__whois_data

    @property
    def rdap_data(self) -> Dict[str, Any]:
        """A dictionary containing the parsed RDAP data."""
        return self.__rdap_data

    @property
    def servers(self) -> Set[str]:
        """A set of WHOIS servers that were queried."""
        return self.__servers

    @property
    def raw(self) -> bytes:
        """A bytes object containing the raw WHOIS data."""
        return self.__raw

    @property
    def domain(self) -> Union[str, int]:
        """The domain/ip/asn that was queried."""
        return self.__domain

    @property
    def expiration_date(self) -> Optional[datetime]:
        """The expiration date of the domain (if available)."""
        return self.expires_date

    @property
    def success(self) -> bool:
        """A boolean indicating whether the query was successful."""
        return self.__success

    @property
    def error(self) -> Optional[Tuple[str, Optional[Exception]]]:
        """A tuple containing the error message and exception (if any)."""
        return self.__error

    def __str__(self):
        return self.__raw.decode(
            self.__get_decode_encoding(self.__raw), errors=self.__encoding_errors
        )

    def __repr__(self):
        return f'WHOIS(domain="{self.__domain}", success={self.__success})'

    def get(self, key: str, default=None):
        """Get a value from the parsed WHOIS data."""
        return self.__whois_data.get(key.upper(), default)

    def __getitem__(self, key: str):
        return self.__whois_data[key.upper()]


def registration_data_lookup(domain: Union[str, int], timeout: int = 10) -> dict:
    """Lookup the registration data for a Domain Name/IP Address/AS Number.

    :param domain: The domain/ip/ans to lookup.
    :param timeout: The timeout for the socket connection.
    :return: A WHOIS object.
    """
    if validate_ip(domain):
        return ip_registration_data_lookup(domain, timeout)
    if validate_asn(domain):
        return asn_registration_data_lookup(domain, timeout)
    # If the `domain` variable is an isinstance of int then it would have passed the
    # `validate_asn` check and the function would have returned. Therefore, we can
    # assume that the `domain` variable is an isinstance of str.
    return domain_registration_data_lookup(domain, timeout)  # type: ignore
