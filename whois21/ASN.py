# whois21.ASN.py

import os
import json

from typing import Union, List
from ipaddress import ip_address

import log21
import requests
import importlib_resources

__all__ = ['download_asn_json', 'get_asn_dict', 'Service', 'get_asn_services', 'ip_registration_data_lookup_',
           'ip_registration_data_lookup', 'validate_ip']


def validate_ip(ip: str):
    """
    Validates an ip.

    :param ip: The ip to validate.
    :return: True if the ip is valid, False otherwise.
    """
    try:
        ip_address(ip)
        return True
    except ValueError:
        return False


def download_asn_json(save_path: Union[str, os.PathLike] = None) -> str:
    """
    Downloads the asn.json file containing the RDAP bootstrap file for Autonomous System Number allocations from
    https://data.iana.org/rdap/asn.json.

    :param save_path: The path to save the file to(default: site-packages/whois21/asn.json).
    :return: The path to the downloaded file.
    """

    if not save_path:
        save_path = importlib_resources.files('whois21') / 'asn.json'

    if not os.path.exists(save_path):
        os.makedirs(os.path.dirname(save_path), exist_ok=True)

    log21.debug(f'Downloading asn.json file to {save_path}.')

    with open(save_path, 'wb') as f:
        f.write(requests.get('https://data.iana.org/rdap/asn.json').content)

    return str(save_path)


def get_asn_dict(force_download: bool = False, path: Union[str, os.PathLike] = None) -> dict:
    """
    Returns a dictionary of the asn.json file.

    :param force_download: If True, the asn.json file will be downloaded again.
    :param path: The path to the asn.json file.
    :return: A dictionary of the asn.json file.
    """

    if not path:
        path = importlib_resources.files('whois21') / 'asn.json'

    if not os.path.exists(path) or force_download:
        download_asn_json(path)

    with open(path, 'r') as f:
        return json.load(f)


class Service:
    ranges: List[range]
    addresses: List[str]

    def __init__(self, service: List[List[str]]):
        if not isinstance(service, List):
            raise TypeError('`service` must be a List.')
        if len(service) != 2:
            raise ValueError('`service` must be a List containing 2 lists of string.')
        self.__ranges: List[range] = [range(*map(int, range_.split('-'))) for range_ in service[0]]
        self.__addresses: List[str] = service[1]

    @property
    def ranges(self) -> List[range]:
        return self.__ranges

    @property
    def addresses(self) -> List[str]:
        return self.__addresses

    def __iter__(self):
        for range_ in self.__ranges:
            for i in range_:
                yield i

    def __repr__(self):
        return f'Service(ranges={self.__ranges}, addresses={self.__addresses})'


def get_asn_services(force_download: bool = False, path: Union[str, os.PathLike] = None) -> \
        List[Service]:
    """
    Returns the list of services in the asn.json file.

    :param force_download: If True, the asn.json file will be downloaded again.
    :param path: The path to the asn.json file.
    :return: The list of services in the asn.json file.
    """
    asn = get_asn_dict(force_download, path)
    return [Service(service) for service in asn.get('services', [])]


def ip_registration_data_lookup_(ip: str, timeout: int = 10) -> List[dict]:
    """
    Gets an ip's RDAP information from registry operators and/or registrars in real-time.

    :param ip: The ip to lookup.
    :param timeout: The timeout for the request.
    :return: A list of dictionaries containing the RDAP information.
    """
    if not validate_ip(ip):
        raise ValueError('`ip` must be a valid ip address.')

    rdaps = list()

    def get_rdap(url: str):
        """
        Gets the RDAP information from a link.

        :param url: The url to get the RDAP information from.
        :return:
        """
        if not url:
            return

        log21.debug(f'Getting domain registration data from {url}.')

        response = requests.get(url, timeout=timeout)
        response_json = response.json()
        if response.status_code == 200 and (not response_json.get('errorCode') and not response_json.get('error')):
            if response_json not in rdaps:
                rdaps.append(response_json)

                # Checks if there is another RDAP link that might have more information.
                for link in response_json.get('links', []):
                    if link.get('rel') != 'self' and link.get('type') == 'application/rdap+json':
                        get_rdap(link.get('href'))

    for service in get_asn_services():
        for service_url in service.addresses:
            try:
                get_rdap(os.path.join(service_url, 'ip/', ip))
            except Exception as e:
                log21.debug(f'Error getting RDAP information from {service_url}: {e.__class__.__name__}: {e}')

    return rdaps


def ip_registration_data_lookup(ip: str, timeout: int = 10) -> dict:
    """
    Gets an ip's RDAP information from registry operators and/or registrars in real-time.

    :param ip: The ip to lookup.
    :param timeout: The timeout for the request.
    :return: A dictionary containing the registration data.
    """
    info = dict()

    def add_info(info_, key_, data: Union[dict, list]):
        """
        Adds information to the info dictionary.

        :param info_: The info dictionary.
        :param key_: The key to add the data to.
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

    rdaps = ip_registration_data_lookup_(ip, timeout)

    for rdap in rdaps:
        rdap.pop('links', None)
        add_info(info, None, rdap)

    return info
