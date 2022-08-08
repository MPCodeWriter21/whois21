# whois21.DNS.py

import os
import json

from typing import Union, List

import log21
import requests
import importlib_resources

__all__ = ['download_dns_json', 'get_dns_dict', 'get_dns_services', 'domain_registration_data_lookup_',
           'domain_registration_data_lookup', 'Service']


def download_dns_json(save_path: Union[str, os.PathLike] = None) -> str:
    """
    Downloads the dns.json file containing the RDAP bootstrap file for Domain Name System registrations from
    https://data.iana.org/rdap/dns.json.

    :param save_path: The path to save the file to(default: site-packages/whois21/dns.json).
    :return: The path to the downloaded file.
    """

    if not save_path:
        save_path = importlib_resources.files('whois21') / 'dns.json'

    if not os.path.exists(save_path):
        os.makedirs(os.path.dirname(save_path), exist_ok=True)

    log21.debug(f'Downloading dns.json file to {save_path}')

    with open(save_path, 'wb') as f:
        f.write(requests.get('https://data.iana.org/rdap/dns.json').content)

    return str(save_path)


def get_dns_dict(force_download: bool = False, path: Union[str, os.PathLike] = None) -> dict:
    """
    Returns a dictionary of the dns.json file.

    :param force_download: If True, the dns.json file will be downloaded again.
    :param path: The path to the dns.json file.
    :return: A dictionary of the dns.json file.
    """

    if not path:
        path = importlib_resources.files('whois21') / 'dns.json'

    if not os.path.exists(path) or force_download:
        download_dns_json(path)

    with open(path, 'r') as f:
        return json.load(f)


class Service:
    domains: List[str]
    address: str

    def __init__(self, service: List[List[str]]):
        if not isinstance(service, List):
            raise TypeError('`service` must be a List.')
        if len(service) != 2:
            raise ValueError('`service` must be a List containing 2 lists of string.')
        self.__domains: List[str] = service[0]
        self.__address: str = service[1][-1]

    @property
    def domains(self) -> List[str]:
        return self.__domains

    @property
    def address(self) -> str:
        return self.__address

    def __iter__(self):
        for item in self.__domains:
            yield item


def get_dns_services(force_download: bool = False, path: Union[str, os.PathLike] = None) -> \
        List[Service]:
    """
    Returns the list of services in the dns.json file.

    :param force_download: If True, the dns.json file will be downloaded again.
    :param path: The path to the dns.json file.
    :return: The list of services in the dns.json file.
    """
    dns = get_dns_dict(force_download, path)
    return [Service(service) for service in dns.get('services', [])]


def domain_registration_data_lookup_(domain: str, timeout: int = 10) -> List[dict]:
    """
    Gets a domain's RDAP information from registry operators and/or registrars in real-time.
    References:
        + https://www.rfc-editor.org/rfc/rfc7484.html

    :param domain: The domain to lookup.
    :param timeout: The timeout for the request.
    :return: A list of dictionaries containing the RDAP information.
    """
    split = domain.split('.')
    domains = ['.'.join(split[i:]) for i in range(len(split))]

    rdaps = list()

    def get_rdap(url: str):
        """
        Gets the RDAP information from a URL.

        :param url: The URL to get the RDAP information from.
        :return: A dictionary containing the RDAP information.
        """
        if not url:
            return

        log21.debug(f'Getting domain registration data from {url}')

        response = requests.get(url, timeout=timeout)
        response_json = response.json()
        if response.status_code == 200 and response_json.get('ldhName'):
            if response_json not in rdaps:
                rdaps.append(response_json)

                # Checks if there is another RDAP server to get the RDAP information from.
                for link in response_json.get('links', []):
                    if link.get('rel') != 'self' and link.get('type') == 'application/rdap+json':
                        get_rdap(link.get('href'))

    for service in get_dns_services():
        if any((tld in service) for tld in domains):
            service_url = service.address
            try:
                get_rdap(os.path.join(service_url, 'domain/', domain))
            except Exception as e:
                log21.debug(f'Error getting domain registration data from {service_url}: {e.__class__.__name__}: {e}')

    return rdaps


def domain_registration_data_lookup(domain: str, timeout: int = 10) -> dict:
    """
    Gets a domain's RDAP information from registry operators and/or registrars in real-time.

    :param domain: The domain to lookup.
    :param timeout: The timeout for the request.
    :return: A dictionary containing the registration data.
    """
    info = dict()

    def add_info(info_, key_, data: Union[dict, list]):
        """
        Adds information to the info dictionary.

        :param info_: The info dictionary.
        :param key_: The key to add the information to.
        :param data: The data to add.
        :return:
        """
        if key_:
            if key_ in info_:
                part = info_[key_]
            else:
                if isinstance(data, dict):
                    part = info_[key_] = dict()
                elif isinstance(data, list):
                    part = info_[key_] = list()
                else:
                    raise TypeError('data must be a dict or list')
        else:
            part = info_

        if isinstance(data, dict):
            for key, value in data.items():
                if key not in part:
                    part[key] = value
                else:
                    if isinstance(part[key], list) and isinstance(value, list):
                        add_info(info_, key, value)
                    elif isinstance(part[key], dict) and isinstance(value, dict):
                        add_info(info_, key, value)
                    else:
                        # Throw it away
                        pass
        elif isinstance(data, list):
            if isinstance(part, list):
                part.extend(data)
            else:
                # Throw it away
                pass

    rdaps = domain_registration_data_lookup_(domain, timeout)

    for rdap in rdaps:
        rdap.pop('links', None)
        add_info(info, None, rdap)

    return info
