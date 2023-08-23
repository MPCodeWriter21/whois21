# whois21.ASN.py

import os
import json
from typing import List, Union, Optional

import log21
import requests
import importlib_resources

__all__ = [
    'validate_asn', 'download_asn_json', 'get_asn_dict', 'Service', 'get_asn_services',
    'asn_registration_data_lookup_', 'asn_registration_data_lookup'
]


def validate_asn(asn: Union[int, str]) -> Union[int, bool]:
    """Validates an Autonomous System Number.

    :param asn: The ASN to validate.
    :return: An integer if the ASN is valid, False if not.
    """

    if isinstance(asn, int):
        return asn
    if isinstance(asn, str):
        try:
            if asn.startswith('AS'):
                return int(asn[2:])
            return int(asn)
        except ValueError:
            return False
    return False


def download_asn_json(
    *, save_path: Optional[Union[str, os.PathLike]] = None, timeout: int = 10
) -> str:
    """Downloads the asn.json file containing the RDAP bootstrap file for Autonomous
    System Number allocations from data.iana.org/rdap/asn.json.

    :param save_path: The path to save the file to(default: site-
        packages/whois21/asn.json).
    :param timeout: The timeout for the request.
    :return: The path to the downloaded file.
    """

    if not save_path:
        save_path = str(importlib_resources.files('whois21') / 'asn.json')

    if not os.path.exists(save_path):
        os.makedirs(os.path.dirname(save_path), exist_ok=True)

    log21.debug(f'Downloading asn.json file to {save_path}.')

    with open(save_path, 'wb') as file:
        file.write(
            requests.get('https://data.iana.org/rdap/asn.json', timeout=timeout).content
        )

    return str(save_path)


def get_asn_dict(
    *,
    force_download: bool = False,
    path: Optional[Union[str, os.PathLike]] = None
) -> dict:
    """Returns a dictionary of the asn.json file.

    :param force_download: If True, the asn.json file will be downloaded again.
    :param path: The path to the asn.json file.
    :return: A dictionary of the asn.json file.
    """

    if not path:
        path = str(importlib_resources.files('whois21') / 'asn.json')

    if not os.path.exists(path) or force_download:
        download_asn_json(save_path=path)

    if os.stat(path).st_size == 0:
        download_asn_json(save_path=path)

    with open(path, 'r', encoding='utf-8') as file:
        return json.load(file)


class Service:
    """A class representing a service.

    A service contains a list of ranges of AS numbers and a list RDAP URLs for those
    ranges.
    """

    def __init__(self, service: List[List[str]]):
        """Initializes the Service class.

        :param service: A list of lists of string representing the service.
        """
        if not isinstance(service, List):
            raise TypeError('`service` must be a List.')
        if len(service) != 2:
            raise ValueError('`service` must be a List containing 2 lists of string.')
        self.__ranges: List[range] = [
            range(*map(int, range_.split('-'))) for range_ in service[0]
        ]
        self.__addresses: List[str] = service[1]

    @property
    def ranges(self) -> List[range]:
        """Returns a list of ranges."""
        return self.__ranges

    @property
    def addresses(self) -> List[str]:
        """Returns a list of addresses."""
        return self.__addresses

    def __iter__(self):
        for range_ in self.__ranges:
            for i in range_:
                yield i

    def __repr__(self):
        return f'Service(ranges={self.__ranges}, addresses={self.__addresses})'


def get_asn_services(
    force_download: bool = False,
    path: Optional[Union[str, os.PathLike]] = None
) -> List[Service]:
    """Returns the list of services present in the asn.json file.

    :param force_download: If True, the asn.json file will be downloaded again.
    :param path: The path to the asn.json file.
    :return: The list of services in the asn.json file.
    """
    asn = get_asn_dict(force_download=force_download, path=path)
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


def asn_registration_data_lookup_(asn: Union[int, str],
                                  timeout: int = 10) -> List[dict]:
    """Gets an Autonomous System Number (ASN) registration data from the RDAP service.

    :param asn: The AS Number to lookup.
    :param timeout: The timeout for the request.
    :return: A list of dictionaries containing the RDAP information.
    """

    try:
        asn = int(asn)
    except ValueError:
        raise ValueError('`asn` must be an integer!') from None

    rdaps = []
    for service in get_asn_services():
        for range_ in service.ranges:
            if asn in range_:
                for service_url in service.addresses:
                    try:
                        _get_rdap(
                            os.path.join(service_url, 'autnum/', str(asn)),
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


def asn_registration_data_lookup(asn: Union[int, str], timeout: int = 10) -> dict:
    """Gets an ASN's registration data from the RDAP service.

    :param asn: The ASN to get the registration data for.
    :param timeout: The timeout for the request.
    :return: A dictionary containing the registration data.
    """
    info = {}

    rdaps = asn_registration_data_lookup_(asn, timeout)

    for rdap in rdaps:
        rdap.pop('links', None)
        __add_info(info, None, rdap)

    return info
