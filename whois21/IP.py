# whois21.IP.py

import os
import json
from typing import Any, List, Union, Optional
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network

import log21
import requests
import importlib_resources

__all__ = [
    'download_ipv4_json', 'get_ipv4_dict', 'download_ipv6_json', 'get_ipv6_dict',
    'Service', 'get_ipv4_services', 'get_ipv6_services', 'ip_registration_data_lookup_',
    'ip_registration_data_lookup', 'validate_ip'
]

IPNetwork = Union[IPv4Network, IPv6Network]


def validate_ip(ip: Union[str, Any]):
    """Validates an ip.

    :param ip: The ip to validate.
    :return: True if the ip is valid, False otherwise.
    """
    try:
        ip_address(ip)
        return True
    except ValueError:
        return False


def download_ipv4_json(
    *, save_path: Optional[Union[str, os.PathLike]] = None, timeout: int = 10
) -> str:
    """Downloads the ipv4.json file containing the RDAP servers for different ip ranges.

    :param save_path: The path to save the file to(default: site-
        packages/whois21/ipv4.json).
    :param timeout: The timeout for the request.
    :return: The path to the downloaded file.
    """

    if not save_path:
        save_path = str(importlib_resources.files('whois21') / 'ipv4.json')

    if not os.path.exists(save_path):
        os.makedirs(os.path.dirname(save_path), exist_ok=True)

    log21.debug(f'Downloading ipv4.json file to {save_path}.')

    with open(save_path, 'wb') as file:
        file.write(
            requests.get('https://data.iana.org/rdap/ipv4.json',
                         timeout=timeout).content
        )

    return str(save_path)


def get_ipv4_dict(
    *,
    force_download: bool = False,
    path: Optional[Union[str, os.PathLike]] = None
) -> dict:
    """Returns a dictionary of the ipv4.json file.

    :param force_download: If True, the ipv4.json file will be downloaded again.
    :param path: The path to the ipv4.json file.
    :return: A dictionary of the ipv4.json file.
    """

    if not path:
        path = str(importlib_resources.files('whois21') / 'ipv4.json')

    if not os.path.exists(path) or force_download:
        download_ipv4_json(save_path=path)

    if os.stat(path).st_size == 0:
        download_ipv4_json(save_path=path)

    with open(path, 'r', encoding='utf-8') as file:
        return json.load(file)


def download_ipv6_json(
    *, save_path: Optional[Union[str, os.PathLike]] = None, timeout: int = 10
) -> str:
    """Downloads the ipv6.json file containing the RDAP servers for different ip ranges.

    :param save_path: The path to save the file to(default: site-
        packages/whois21/ipv6.json).
    :param timeout: The timeout for the request.
    :return: The path to the downloaded file.
    """

    if not save_path:
        save_path = str(importlib_resources.files('whois21') / 'ipv6.json')

    if not os.path.exists(save_path):
        os.makedirs(os.path.dirname(save_path), exist_ok=True)

    log21.debug(f'Downloading ipv6.json file to {save_path}.')

    with open(save_path, 'wb') as file:
        file.write(
            requests.get('https://data.iana.org/rdap/ipv6.json',
                         timeout=timeout).content
        )

    return str(save_path)


def get_ipv6_dict(
    *,
    force_download: bool = False,
    path: Optional[Union[str, os.PathLike]] = None
) -> dict:
    """Returns a dictionary of the ipv6.json file.

    :param force_download: If True, the ipv6.json file will be downloaded again.
    :param path: The path to the ipv6.json file.
    :return: A dictionary of the ipv6.json file.
    """

    if not path:
        path = str(importlib_resources.files('whois21') / 'ipv6.json')

    if not os.path.exists(path) or force_download:
        download_ipv6_json(save_path=path)

    if os.stat(path).st_size == 0:
        download_ipv6_json(save_path=path)

    with open(path, 'r', encoding='utf-8') as file:
        return json.load(file)


class Service:
    """A class representing a service.

    A service contains a list of ranges of IP ranges and a list of RDAP servers that can
    be used to query the IP addresses in those ranges.
    """

    def __init__(self, service: List[List[str]]):
        """Initializes the Service class.

        :param service: A list of lists of string representing the service.
        """
        if not isinstance(service, List):
            raise TypeError('`service` must be a List.')
        if len(service) != 2:
            raise ValueError('`service` must be a List containing 2 lists of string.')
        self.__networks: List[IPNetwork] = [ip_network(range_) for range_ in service[0]]
        self.__addresses: List[str] = service[1]

    @property
    def networks(self) -> List[IPNetwork]:
        """Returns a list of ranges."""
        return self.__networks

    @property
    def addresses(self) -> List[str]:
        """Returns a list of addresses."""
        return self.__addresses

    def __iter__(self):
        for network in self.__networks:
            for item in network:
                yield item

    def __repr__(self):
        return f'Service(ranges={self.__networks}, addresses={self.__addresses})'


def get_ipv4_services(
    force_download: bool = False,
    path: Optional[Union[str, os.PathLike]] = None
) -> List[Service]:
    """Returns the list of services present in the ipv4.json file.

    :param force_download: If True, the ipv4.json file will be downloaded again.
    :param path: The path to the ipv4.json file.
    :return: The list of services in the ipv4.json file.
    """
    asn = get_ipv4_dict(force_download=force_download, path=path)
    return [Service(service) for service in asn.get('services', [])]


def get_ipv6_services(
    force_download: bool = False,
    path: Optional[Union[str, os.PathLike]] = None
) -> List[Service]:
    """Returns the list of services present in the ipv6.json file.

    :param force_download: If True, the ipv6.json file will be downloaded again.
    :param path: The path to the ipv6.json file.
    :return: The list of services in the ipv6.json file.
    """
    asn = get_ipv6_dict(force_download=force_download, path=path)
    return [Service(service) for service in asn.get('services', [])]


def _get_rdap(url: str, rdaps: List[dict], timeout: int = 10) -> None:
    """Gets the RDAP information from a link.

    :param url: The url to get the RDAP information from.
    :param rdaps: The list to append the RDAP information to.
    :param timeout: The timeout for the request.
    :return:
    """
    if not url:
        return

    log21.debug(f'Getting domain registration data from {url}.')

    response = requests.get(url, timeout=timeout)
    response_json = response.json()
    if response.status_code == 200 and (not response_json.get('errorCode')
                                        and not response_json.get('error')):
        if response_json not in rdaps:
            rdaps.append(response_json)

            # Checks if there is another RDAP link that might have more information.
            for link in response_json.get('links', []):
                if link.get('rel') != 'self' and link.get('type'
                                                          ) == 'application/rdap+json':
                    _get_rdap(link.get('href'), rdaps, timeout=timeout)


def ip_registration_data_lookup_(ip: str, timeout: int = 10) -> List[dict]:
    """Gets an IP address's RDAP information from registry operators and/or registrars
    in real-time.

    :param ip: The ip to lookup.
    :param timeout: The timeout for the request.
    :return: A list of dictionaries containing the RDAP information.
    """
    try:
        address = ip_address(ip)
    except ValueError:
        raise ValueError('`ip` must be a valid ip address.') from None

    rdaps = []

    if address.version == 4:
        services = get_ipv4_services()
    else:
        services = get_ipv6_services()

    for service in services:
        for network in service.networks:
            if address in network:
                for service_url in service.addresses:
                    try:
                        _get_rdap(
                            os.path.join(service_url, 'ip/', ip),
                            rdaps,
                            timeout=timeout
                        )
                    except Exception as ex:  # pylint: disable=broad-except
                        log21.debug(
                            f'Error getting RDAP information from {service_url}:'
                            f' {ex.__class__.__name__}: {ex}'
                        )

    return rdaps


def __add_info(info, key, data: Union[dict, list]):
    """Adds information to the info dictionary.

    :param info: The info dictionary.
    :param key: The key to add the data to.
    :param data: The data to add.
    :return:
    """
    if key:
        if key in info:
            part = info[key]
        else:
            if isinstance(data, dict):
                part = info[key] = []
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


def ip_registration_data_lookup(ip: Union[str, Any], timeout: int = 10) -> dict:
    """Gets an IP address's RDAP information from registry operators and/or registrars
    in real-time.

    :param ip: The ip to lookup.
    :param timeout: The timeout for the request.
    :return: A dictionary containing the registration data.
    """
    info = {}

    rdaps = ip_registration_data_lookup_(ip, timeout)

    for rdap in rdaps:
        rdap.pop('links', None)
        __add_info(info, None, rdap)

    return info
