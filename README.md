whois21
=====

![version](https://img.shields.io/pypi/v/whois21)
![stars](https://img.shields.io/github/stars/MPCodeWriter21/whois21)
![forks](https://img.shields.io/github/forks/MPCodeWriter21/whois21)
![repo size](https://img.shields.io/github/repo-size/MPCodeWriter21/whois21)
[![CodeFactor](https://www.codefactor.io/repository/github/mpcodewriter21/whois21/badge)](https://www.codefactor.io/repository/github/mpcodewriter21/whois21)

WHOIS21 is a simple and easy to use python package that lets you easily query whois information of a domain.

Features
--------

### WHOIS

+ Query whois information of a TLD from various whois servers and parse the results.
+ Get the Registration Information of a domain from different RDAP servers and parse the results.
+ Get IP information from ip-api.com.
+ Any idea? Feel free to [open an issue](https://github.com/MPCodeWriter21/whois21/issues) or submit a pull request.

![issues](https://img.shields.io/github/issues/MPCodeWriter21/whois21)
![contributors](https://img.shields.io/github/contributors/MPCodeWriter21/whois21)

Installation
------------

Well, this is a python package so the first thing you need is python.

If you don't have python installed, please visit [Python.org](https://python.org) and install the latest version of
python based on your OS.

Then you can install whois21 using pip module:

```shell
# Use this command to get the latest version from pypi.org and install it automatically
python -m pip install whois21 -U

# OR
# Download the release file from GitHub: https://github.com/MPCodeWriter21/whois21/releases
# And install it using this command
pip install whois21-x.x.x.tar.gz
```

Or you can clone [the repository](https://github.com/MPCodeWriter21/whois21) and run:

```shell
python -m build .
```

### Dependencies

+ [requests](https://requests.readthedocs.io/en/master/): Used for:
    - Downloading list of whois and RDAP servers.
    - Downloading RDAP information.
+ [importlib_resources](https://importlib-resources.readthedocs.io/en/latest/): Used for:
    - Getting the path to the whois21 package installation directory(for saving server lists).
+ [log21](https://github.com/MPCodeWriter21/log21): Used for:
    - Colorized Logging.
    - Printing collected data in pprint or tree format.
+ [os](https://docs.python.org/3/library/os.html) (A core python module): Used for:
    - Working with files and directories.
+ [socket](https://docs.python.org/3/library/socket.html) (A core python module): Used for:
    - Establishing TCP connection to the whois server.
+ [json](https://docs.python.org/3/library/json.html) (A core python module): Used for:
    - Parsing JSON data from RDAP servers.
    - Parsing RDAP server list.
    - Saving collected whois or/and RDAP data to a file.
    - Loading some package data from a file.
+ [datetime](https://docs.python.org/3/library/datetime.html) (A core python module): Used for:
    - Converting Creation/Updated/Expiration date to a usable python datetime object.
+ [ipaddress](https://docs.python.org/3/library/ipaddress.html) (A core python module): Used for:
    - Validating IPv4 and IPv6 addresses.
+ [typing](https://docs.python.org/3/library/typing.html) (A core python module): Used for:
    - Type checking.
    - Type hinting.
+ [re](https://docs.python.org/3/library/re.html) (A core python module): Used for:
    - Matching date-time strings with regular expressions.

Changes
-------

### 1.2.1

Switched from `setup.py` to `pyproject.toml`.

Usage Examples:
---------------

### CLI Examples

+ Example 1: Query whois information of google.com

```shell
# -v : verbose mode
whois21 -v results google.com
```

+ Example 2: Query whois information of 3 domains and save the results to a directory

```shell
# -R : saves the results as raw text
# -np: avoids printing the results to the screen
# -o results: saves the results to `./results` directory 
whois21 -R -np -o results google.com facebook.com pinterest.com
```

+ Example 3: Query whois information of 3 IPs and save the results to a directory

```shell
# Options explained in the examples above
whois21 -R -np -v -o results 1.1.1.1 157.240.20.174 64.91.226.82
```

+ Example 4: Query RDAP information of domains and IPs and save the results to a file

```shell
# -r: Gets the RDAP information of the queried domains and IPs
whois21 -np -o results -o results -r microsoft.com python.org 140.82.121.3 185.147.178.13
```

### Python Code Examples

+ Example 1: Query whois information of GitHub.com using WHOIS class.

```python3
# First step is to import the package
import whois21

query = 'github.com'

# Second step is to create an instance of the WHOIS class
whois = whois21.WHOIS(query)

# Third step is to check if the operation was successful
if not whois.success:
    print(whois.error)
    exit()

# And basically you are done!
# Now you can print the results
import log21  # I use log21 to print the results in a cool way 8D

# Print the results in a nice way
# PPrint the dictionary
log21.pprint(whois.whois_data)
# Tree-Print the dictionary
log21.tree_print(whois.whois_data)

# Or you can print the results in as raw text
print(whois.raw.decode('utf-8'))

# Or you can access each part of the results individually
print(f'Creation date   : {whois.creation_date}')
print(f'Expiration date : {whois.expires_date}')
print(f'Updated date    : {whois.updated_date}')

```

About
-----
Author: CodeWriter21 (Mehrad Pooryoussof)

GitHub: [MPCodeWriter21](https://github.com/MPCodeWriter21)

Telegram Channel: [@CodeWriter21](https://t.me/CodeWriter21)

Aparat Channel: [CodeWriter21](https://www.aparat.com/CodeWriter21)

### License

![License](https://img.shields.io/github/license/MPCodeWriter21/whois21)

[apache-2.0](http://www.apache.org/licenses/LICENSE-2.0)

### Donate

In order to support this project you can donate some crypto of your choice 8D

[Donate Addresses](https://github.com/MPCodeWriter21/whois21/blob/master/DONATE.md)

Or if you can't, give [this project](https://github.com/MPCodeWriter21/whois21) a star on GitHub :)

References
----------

+ WHOIS (Wikipedia): [https://en.wikipedia.org/wiki/WHOIS](https://en.wikipedia.org/wiki/WHOIS)
+ Domains: [https://www.iana.org/domains/root/db/](https://www.iana.org/domains/root/db/)
+ Registration Data Access Protocol (RDAP) (
  Wikipedia): [https://en.wikipedia.org/wiki/Registration_Data_Access_Protocol](https://en.wikipedia.org/wiki/Registration_Data_Access_Protocol)
+ RDAP Response Profile (
  PDF): [https://www.icann.org/en/system/files/files/rdap-response-profile-15feb19-en.pdf](https://www.icann.org/en/system/files/files/rdap-response-profile-15feb19-en.pdf)
+ Registration Data Access Protocol (RDAP) Query
  Format: [https://www.rfc-editor.org/rfc/rfc7482.html](https://www.rfc-editor.org/rfc/rfc7482.html)
+ Registration Data Access Protocol (RDAP) Object
  Tagging: [https://www.rfc-editor.org/rfc/rfc8521.html](https://www.rfc-editor.org/rfc/rfc8521.html)
+ Finding the Authoritative Registration Data (RDAP)
  Service: [https://www.rfc-editor.org/rfc/rfc7484.html](https://www.rfc-editor.org/rfc/rfc7484.html)
+ JSON Responses for the Registration Data Access Protocol (RDAP):
  [https://www.rfc-editor.org/rfc/rfc7483](https://www.rfc-editor.org/rfc/rfc7483)
+ Registration Data Access Protocol (RDAP) Partial
  Response: [https://www.rfc-editor.org/rfc/rfc8982.html](https://www.rfc-editor.org/rfc/rfc8982.html)
+ vCard Format Specification: [https://www.rfc-editor.org/rfc/rfc6350.txt](https://www.rfc-editor.org/rfc/rfc6350.txt)
+ vCard (Wikipedia): [https://en.wikipedia.org/wiki/VCard](https://en.wikipedia.org/wiki/VCard)
+ Notes on vCard, LDIF and mappings to
  RDF: [https://www.w3.org/2002/12/cal/vcard-notes.html](https://www.w3.org/2002/12/cal/vcard-notes.html)
