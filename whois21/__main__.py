# whois21.__main__.py

import os
import json

import log21
import whois21


def get_filename(directory: str, domain: str, format_: str = 'json') -> str:
    """
    Gets a filename to store the registration data in.

    :param directory: The directory to store the registration data in.
    :param domain: The domain to get the name for.
    :param format_: The format to store the registration data in.
    :return: The filename.
    """
    name = domain + '.' + format_
    # Remove invalid characters
    for char in '<>:"/\\|?*':
        name = name.replace(char, '_')

    i = 2
    filename = os.path.join(directory, name)
    while os.path.exists(filename):
        name = f'{domain}-{i}.{format_}'
        filename = os.path.join(directory, name)
        i += 1

    return filename


def main():
    parser = log21.ColorizingArgumentParser()
    parser.add_argument('domains', help='The domain/ip to lookup.', type=str, nargs='*')
    parser.add_argument('-r', '--registration-data', action='store_true',
                        help='Lookup the registration data for a domain.')
    parser.add_argument('-to', '--timeout', type=int, default=10,
                        help='The time out for the WHOIS request(default=10).')
    parser.add_argument('-t', '--tree-print', action='store_true',
                        help='Print the registration data in a tree format.')
    parser.add_argument('-o', '--output', help='The output folder.', type=str)
    parser.add_argument('-R', '--raw', action='store_true', help='Print/save the raw whois data.')
    parser.add_argument('-np', '--no-print', action='store_true', help='Don\'t print the registration/whois data.')
    parser.add_argument('-q', '--quiet', action='store_true', help='Don\'t print any output.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output.')
    parser.add_argument('-V', '--version', action='version', version=f'whois21 {whois21.__version__}')
    args = parser.parse_args()

    if args.verbose and args.quiet:
        parser.error('Cannot use both -v and -q.')
    if args.verbose:
        log21.basic_config(level=log21.DEBUG)
    elif args.quiet:
        log21.basic_config(level=log21.ERROR)

    if args.no_print and args.tree_print:
        parser.error('Cannot use both -np and -t.')
    if args.raw and args.tree_print:
        parser.error('Cannot use both -R and -t.')
    if args.raw and args.registration_data:
        log21.warn('-R will not effect results from -r.')
    if args.no_print:
        if not args.output:
            parser.error('Must specify an output folder with -o when using -np.')
        print_result = lambda *args, **kwargs: None
    elif args.tree_print:
        print_result = log21.tree_print
    else:
        print_result = log21.pprint

    if args.output:
        os.makedirs(args.output, exist_ok=True)

    if args.domains:
        if args.raw and not args.registration_data:
            for domain in args.domains:
                log21.info(f'Looking up {domain}...')
                result = whois21.WHOIS(domain, timeout=args.timeout)
                if result.raw:
                    if not args.no_print:
                        print(result)
                    if args.output:
                        filename = get_filename(args.output, domain, 'txt')
                        with open(filename, 'wb') as file:
                            file.write(result.raw)
                        log21.info(f'Saved whois data to {filename}.')
                elif result.whois_data:
                    if not args.no_print:
                        print_result(result.whois_data)
                    if args.output:
                        filename = get_filename(args.output, domain, 'json')
                        with open(filename, 'w') as file:
                            json.dump(result.whois_data, file, indent=4)
                        log21.info(f'Saved whois data to {filename}.')
                elif result.error:
                    log21.error(result.error)
                else:
                    log21.error(f'Unknown error for {domain}.')
        else:
            if args.registration_data:
                for domain in args.domains:
                    log21.info(f'Looking up registration data for {domain}...')
                    result = whois21.WHOIS(domain, timeout=args.timeout, force_rdap=True).rdap_data
                    print_result(result)
                    if args.output:
                        filename = get_filename(args.output, domain)
                        with open(filename, 'w') as file:
                            json.dump(result, file, indent=4)
                        log21.info(f'Saved registration data to {filename}.')
            else:
                for domain in args.domains:
                    log21.info(f'Looking up {domain}...')
                    result = whois21.WHOIS(domain, timeout=args.timeout).whois_data
                    print_result(result)
                    if args.output:
                        filename = get_filename(args.output, domain)
                        with open(filename, 'w') as file:
                            json.dump(result, file, indent=4)
                        log21.info(f'Saved whois data to {filename}.')
    else:
        parser.print_help()


def run():
    try:
        main()
    except KeyboardInterrupt:
        log21.error('KeyboardInterrupt: Exiting...')


if __name__ == '__main__':
    run()
