# whois21.API.py

from typing import Union, Sequence

import log21
import requests

from .ASN import validate_ip


def lookup_ip_ip_api(ip: str, fields: Union[Sequence[str], str] = '61439', lang: str = 'en', timeout: int = 10) -> dict:
    """
    Looks up an ip using ip-api.com.

    :param ip: The ip or domain to look up.
    :param fields: The fields to return. See https://ip-api.com/docs/api:json for more info.
    :param lang: The language to return the data in. See https://ip-api.com/docs/api:json for more info.
    :param timeout: The time-out for the request.
    :return: A dictionary containing the data.
    """

    if isinstance(fields, Sequence) and not isinstance(fields, str):
        fields = ','.join(fields)

    if not isinstance(fields, str):
        raise TypeError('`fields` must be a string or a sequence of strings.')

    log21.debug(f'Looking up {ip} using ip-api.com.')

    return requests.get(f'http://ip-api.com/json/{ip}?fields={fields}&lang={lang}', timeout=timeout).json()


def batch_lookup_ip_ip_api(ips: Sequence[str], fields: Union[Sequence[str], str] = '61439', lang: str = 'en',
                           timeout: int = 10) -> dict:
    """
    Looks up multiple ips using ip-api.com.

    :param ips: The ips to look up.
    :param fields: The fields to return. See https://ip-api.com/docs/api:batch for more info.
    :param lang: The language to return the data in. See https://ip-api.com/docs/api:batch for more info.
    :param timeout: The time-out for the request.
    :return: A dictionary containing the data.
    """

    if not isinstance(ips, Sequence):
        raise TypeError('ips must be a sequence.')

    # Checks if all fields are valid
    for i, ip in enumerate(ips):
        if not validate_ip(ip):
            raise ValueError(f'Invalid ip[{i}]: {ip}')

    ips = list(ips)

    if isinstance(fields, Sequence) and not isinstance(fields, str):
        fields = ','.join(fields)

    if not isinstance(fields, str):
        raise TypeError('`fields` must be a string or a sequence of strings.')

    log21.debug(f'Looking up {ips} using ip-api.com.')

    return requests.get(f'http://ip-api.com/batch?fields={fields}&lang={lang}', json=ips, timeout=timeout).json()
