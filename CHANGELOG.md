Whois21
=====

Help this project by [Donation](DONATE.md)

Changes log
-----------

### 1.4.4

+ Fixed concatenating issue with nameservers.

### 1.4.3

+ Fixed issue #5.
+ Dates are now lists.

### 1.4.2

+ Added new attributes to `WHOIS` class: `emails`, `phone_numbers` and `fax_numbers`
+ Added a new property that contains expiration date(`expiration_date`) to `WHOIS` class
+ Improved WHOIS data parsing (For both human eyes and computer results)

### 1.4.1

+ Made whois run after initializing the `WHOIS` object optional.
+ Tried to decrease the complexity of the code.

### 1.4.0

+ Added IP module and fixed some issues with IP and ASN registration data lookup.
+ Modified the functions responsible for getting json data to download the data if the 
  file exists but is empty.
+ Fixed minor bugs.

### 1.3.0

+ Added the option to specify the encoding to use for encoding and decoding the data in 
  in WHOIS class.
+ Added the option to customize the behavior of the WHOIS class when it encounters an 
  error while encoding or decoding data.
+ Added the feature to automatically detect the encoding of _whois_ response to solve
  decoding issues, such as the one mentioned in issue #2.

### 1.2.1

Switched from `setup.py` to `pyproject.toml`.

### 1.2.0

Added ip-api.com API support.

### 1.1.2

Fixed KeyboardInterrupt handling with `whois21` command.

### 1.1.1

Minor Fixes.

### 1.1.0

Added RDAP information collection and parsing support to WHOIS class.

### 1.0.0

Version 1.0.0
