"""Some base functions that will be expanded using partial functions.

NOTE: The functions in this module are not meant to be used by modules or scripts other
than whois21's modules. Use them at your risk.
"""

import os
from typing import Union, Optional

import log21
import requests
import importlib_resources


def download_json(
    file_name: str,
    *,
    save_path: Optional[Union[str, os.PathLike]] = None,
    timeout: int = 10
) -> str:
    """Downloads a json file.

    :param file_name: What has to be passed using `partial` to complete the function.
        It is used for generating the default save path and the download URL.
    :param save_path: The path to save the file to(default: site-
        packages/whois21/file_name).
    :param timeout: The timeout for the request.
    :return: The path to the downloaded file.
    """

    if not save_path:
        save_path = str(importlib_resources.files('whois21') / file_name)

    if not os.path.exists(save_path):
        os.makedirs(os.path.dirname(save_path), exist_ok=True)

    log21.debug(f'Downloading {file_name} file to {save_path}.')

    with open(save_path, 'wb') as file:
        file.write(
            requests.get(f'https://data.iana.org/rdap/{file_name}',
                         timeout=timeout).content
        )

    return str(save_path)
