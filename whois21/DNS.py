# whois21.DNS.py

import os
import json
from typing import List, Union, Optional

import log21
import requests
import importlib_resources

__all__ = [
    'download_dns_json', 'get_dns_dict', 'get_dns_services',
    'domain_registration_data_lookup_', 'domain_registration_data_lookup', 'Service'
]


def download_dns_json(
    *, save_path: Optional[Union[str, os.PathLike]] = None, timeout: int = 10
) -> str:
    """Downloads the dns.json file containing the RDAP bootstrap file for Domain Name
    System registrations from data.iana.org/rdap/dns.json.

    :param save_path: The path to save the file to(default: site-
        packages/whois21/dns.json).
    :param timeout: The timeout for the request.
    :return: The path to the downloaded file.
    """

    if not save_path:
        save_path = str(importlib_resources.files('whois21') / 'dns.json')

    if not os.path.exists(save_path):
        os.makedirs(os.path.dirname(save_path), exist_ok=True)

    log21.debug(f'Downloading dns.json file to {save_path}')

    with open(save_path, 'wb') as file:
        file.write(
            requests.get('https://data.iana.org/rdap/dns.json', timeout=timeout).content
        )

    return str(save_path)


def get_dns_dict(
    *,
    force_download: bool = False,
    path: Optional[Union[str, os.PathLike]] = None
) -> dict:
    """Returns a dictionary of the dns.json file.

    :param force_download: If True, the dns.json file will be downloaded again.
    :param path: The path to the dns.json file.
    :return: A dictionary of the dns.json file.
    """

    if not path:
        path = str(importlib_resources.files('whois21') / 'dns.json')

    if not os.path.exists(path) or force_download:
        download_dns_json(save_path=path)

    if os.stat(path).st_size == 0:
        download_dns_json(save_path=path)

    with open(path, 'r', encoding='utf-8') as file:
        return json.load(file)


class Service:
    """Represents a service from the dns.json file.

    A service contains a of TLDs and the RDAP URLs that can be used to query them.
    """

    def __init__(self, service: List[List[str]]):
        """Initializes a new instance of the Service class.

        :param service: A list of two lists of strings.
        """
        if not isinstance(service, List):
            raise TypeError('`service` must be a List.')
        if len(service) != 2:
            raise ValueError('`service` must be a List containing 2 lists of string.')
        self.__domains: List[str] = service[0]
        self.__address: str = service[1][-1]

    @property
    def domains(self) -> List[str]:
        """Returns a list of TLDs that can be queried using the RDAP URL."""
        return self.__domains

    @property
    def address(self) -> str:
        """Returns the RDAP URL that can be used to query the TLDs."""
        return self.__address

    def __iter__(self):
        for item in self.__domains:
            yield item


def get_dns_services(
    force_download: bool = False,
    path: Optional[Union[str, os.PathLike]] = None
) -> List[Service]:
    """Returns the list of services in the dns.json file.

    :param force_download: If True, the dns.json file will be downloaded again.
    :param path: The path to the dns.json file.
    :return: The list of services in the dns.json file.
    """
    dns = get_dns_dict(force_download=force_download, path=path)
    return [Service(service) for service in dns.get('services', [])]


def _get_rdap(url: str, rdaps: List[dict], timeout: int = 10) -> None:
    """Gets the RDAP information from a URL.

    :param url: The URL to get the RDAP information from.
    :param rdaps: The list to append the RDAP information to.
    :param timeout: The timeout for the request.
    """
    if not url:
        return

    log21.debug(f'Getting domain registration data from {url}')

    response = requests.get(url, timeout=timeout)
    response_json = response.json()
    if response.status_code == 200 and response_json.get('ldhName'):
        if response_json not in rdaps:
            rdaps.append(response_json)

            # Checks if there is another RDAP server to get the RDAP information
            # from.
            for link in response_json.get('links', []):
                if link.get('rel') != 'self' and link.get('type'
                                                          ) == 'application/rdap+json':
                    _get_rdap(link.get('href'), rdaps, timeout=timeout)


def domain_registration_data_lookup_(domain: str, timeout: int = 10) -> List[dict]:
    """Gets a domain's RDAP information from registry operators and/or registrars in
    real-time.

    References:
        + https://www.rfc-editor.org/rfc/rfc7484.html

    :param domain: The domain to lookup.
    :param timeout: The timeout for the request.
    :return: A list of dictionaries containing the RDAP information.
    """
    split = domain.split('.')
    domains = ['.'.join(split[i:]) for i in range(len(split))]

    rdaps = []

    for service in get_dns_services():
        if any((tld in service) for tld in domains):
            service_url = service.address
            try:
                _get_rdap(
                    os.path.join(service_url, 'domain/', domain),
                    rdaps,
                    timeout=timeout
                )
            except Exception as ex:  # pylint: disable=broad-except
                log21.debug(
                    f'Error getting domain registration data from {service_url}: '
                    f'{ex.__class__.__name__}: {ex}'
                )

    return rdaps


def __add_info(info, key, data: Union[dict, list]):
    """Adds information to the info dictionary.

    :param info: The info dictionary.
    :param key: The key to add the information to.
    :param data: The data to add.
    :return:
    """
    if key:
        if key in info:
            part = info[key]
        else:
            if isinstance(data, dict):
                part = info[key] = {}
            elif isinstance(data, list):
                part = info[key] = []
            else:
                raise TypeError('data must be a dict or list')
    else:
        part = info

    if isinstance(data, dict):
        for key_, value in data.items():
            if key_ not in part:
                part[key_] = value
            else:
                if isinstance(part[key_], list) and isinstance(value, list):
                    __add_info(info, key_, value)
                elif isinstance(part[key_], dict) and isinstance(value, dict):
                    __add_info(info, key_, value)
                else:
                    # Throw it away
                    pass
    elif isinstance(data, list):
        if isinstance(part, list):
            part.extend(data)
        else:
            # Throw it away
            pass


def domain_registration_data_lookup(domain: str, timeout: int = 10) -> dict:
    """Gets a domain's RDAP information from registry operators and/or registrars in
    real-time.

    :param domain: The domain to lookup.
    :param timeout: The timeout for the request.
    :return: A dictionary containing the registration data.
    """
    info = {}

    rdaps = domain_registration_data_lookup_(domain, timeout)

    for rdap in rdaps:
        rdap.pop('links', None)
        __add_info(info, None, rdap)

    return info
