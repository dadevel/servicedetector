#!/usr/bin/env python3
from typing import Any
from argparse import ArgumentParser, BooleanOptionalAction, Namespace, RawTextHelpFormatter
from concurrent.futures import ThreadPoolExecutor
from pathlib import PurePath
import csv
import functools
import importlib.resources
import json
import logging
import os
import shutil
import sys
import threading
import traceback

from impacket.dcerpc.v5 import lsad, lsat
from impacket.dcerpc.v5.transport import DCERPCTransportFactory, DCERPC_v5, SMBTransport
from impacket.dcerpc.v5.dtypes import NULL, MAXIMUM_ALLOWED, RPC_UNICODE_STRING
from impacket.dcerpc.v5.lsat import DCERPCSessionError
from impacket.smbconnection import SMBConnection

SOCKET_TIMEOUT = 5

local = threading.local()


class LsaClient():
    def __init__(self, domain: str, username: str, password: str, host: str, kerberos: bool, kdc: str, lmhash: str, nthash: str) -> None:
        self.domain = domain
        self.username = username
        self.password = password
        self.host = host
        self.kerberos = kerberos
        self.lmhash = lmhash
        self.nthash = nthash
        self.kdc = kdc
        self.dce_client: DCERPC_v5 = None  # type: ignore

    def connect(self) -> None:
        rpc_transport: SMBTransport = DCERPCTransportFactory(f'ncacn_np:{self.host}[\\PIPE\\lsarpc]')  # type: ignore
        rpc_transport.set_connect_timeout(SOCKET_TIMEOUT)
        rpc_transport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash)
        if self.kerberos:
            rpc_transport.set_kerberos(self.kerberos, kdcHost=self.kdc)
        rpc_transport.get_dce_rpc
        self.dce_client = rpc_transport.get_dce_rpc()
        self.dce_client.connect()
        self.dce_client.bind(lsat.MSRPC_UUID_LSAT)

    def open_policy(self) -> bytes:
        request = lsad.LsarOpenPolicy2()
        request['SystemName'] = NULL
        request['ObjectAttributes']['RootDirectory'] = NULL
        request['ObjectAttributes']['ObjectName'] = NULL
        request['ObjectAttributes']['SecurityDescriptor'] = NULL
        request['ObjectAttributes']['SecurityQualityOfService'] = NULL
        request['DesiredAccess'] = MAXIMUM_ALLOWED|lsat.POLICY_LOOKUP_NAMES
        resp = self.dce_client.request(request)
        return resp['PolicyHandle']

    def lookup_name(self, policy_handle: bytes, service: str) -> dict[str, Any]:
        request = lsat.LsarLookupNames()
        request['PolicyHandle'] = policy_handle
        request['Count'] = 1
        name1 = RPC_UNICODE_STRING()
        name1['Data'] = f'NT Service\\{service}'
        request['Names'].append(name1)
        request['TranslatedSids']['Sids'] = NULL
        request['LookupLevel'] = lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta
        resp = self.dce_client.request(request)
        return resp


def detect_services(host: str, opts: Namespace) -> None:
    lsa_client = LsaClient(opts.domain, opts.user, opts.password, host, opts.kerberos, opts.dc_ip, opts.lmhash, opts.nthash)
    lsa_client.connect()
    policy_handle = lsa_client.open_policy()

    for service in opts.indicators['service']:
        try:
            lsa_client.lookup_name(policy_handle, service['value'])
            local.log(category=service['category'], product=service['product'], service=service['value'], state='present')
        except DCERPCSessionError as e:
            if e.error_code != 0xc0000073:  # STATUS_NONE_MAPPED
                raise e


def detect_named_pipes(host: str, opts: Namespace) -> None:
    smb_client = SMBConnection(host, host)
    if opts.kerberos:
        smb_client.kerberosLogin(opts.user, opts.password, opts.domain, opts.lmhash, opts.nthash, opts.aeskey, opts.dc_ip)
    else:
        smb_client.login(opts.user, opts.password, opts.domain, opts.lmhash, opts.nthash)

    for file in smb_client.listPath('IPC$', '\\*'):
        pipepath = file.get_longname()
        if opts.debug:
            local.log(category='debug', product='', pipe=pipepath, state='running')
        for pipe in opts.indicators['pipe']:
            if PurePath(pipepath).match(pipe['value']):
                local.log(category=pipe['category'], product=pipe['product'], pipe=pipepath, state='running')


def run_detections(host: str, opts: Namespace) -> bool:
    local.log = functools.partial(log, host=host)
    try:
        detect_services(host, opts)
    except OSError as e:
        local.log(error=str(e.strerror))
        return False
    except Exception as e:
        local.log(error=str(e))
        if opts.debug:
            traceback.print_exception(e, file=sys.stderr)
        return False

    try:
        detect_named_pipes(host, opts)
    except OSError as e:
        local.log(error=str(e.strerror))
        return False
    except Exception as e:
        local.log(error=str(e))
        if opts.debug:
            traceback.print_exception(e, file=sys.stderr)
        return False

    return True


def read_indicators() -> dict[str, list[dict[str, str]]]:
    resources = importlib.resources.files(__package__)
    indicators = dict(pipe=[], process=[], service=[])
    with open(resources/'indicators.csv') as file:  # type: ignore
        reader = csv.DictReader(file)
        for row in reader:
            indicators[row['type']].append(row)
    return indicators


def log(**kwargs: Any) -> None:
    print(json.dumps(kwargs, sort_keys=False), file=sys.stderr)


def main() -> None:
    indicators = read_indicators()
    categories = {product['category'] for products in indicators.values() for product in products}

    help_formatter = lambda prog: RawTextHelpFormatter(prog, max_help_position=round(shutil.get_terminal_size().columns / 2))
    entrypoint = ArgumentParser(description='Detects named pipes and installed services without local admin privileges.', formatter_class=help_formatter)
    entrypoint.add_argument('-c', '--category', choices=categories, metavar='|'.join(categories), help='default: all')
    entrypoint.add_argument('--threads', type=int, default=min((os.cpu_count() or 1) * 4, 16), metavar='UINT', help='default: based on CPU cores')
    entrypoint.add_argument('--debug', action=BooleanOptionalAction, default=False)
    entrypoint.add_argument('hosts', nargs='+', metavar='HOST')

    auth = entrypoint.add_argument_group('auth')
    auth.add_argument('-d', '--domain', default='', metavar='DOMAIN')
    auth.add_argument('-u', '--user', default='', metavar='USERNAME')
    authsecret = auth.add_mutually_exclusive_group()
    authsecret.add_argument('-p', '--password', default='', metavar='PASSWORD')
    authsecret.add_argument('-H', '--hashes', default='', metavar='[LMHASH:]NTHASH', help='authenticate via (over)pass the hash')
    authsecret.add_argument('-a', '--aes-key', default='', metavar='HEXKEY', help='authenticate via pass the key')
    auth.add_argument('-k', '--kerberos', action=BooleanOptionalAction, default=False, help='use Kerberos instead of NTLM')
    auth.add_argument('--dc-ip', action='store', metavar='FQDN|IPADDRESS', help='FQDN or IP of a domain controller, default: value of -d')

    opts = entrypoint.parse_args()
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG if opts.debug else logging.ERROR)
    opts.hosts = set(opts.hosts)

    if not opts.kerberos and not opts.password and not opts.hashes and not opts.aes_key:
        log(error='no authentication secret given')
        exit(1)

    if ':' in opts.hashes:
        opts.lmhash, opts.nthash = opts.hashes.split(':', maxsplit=1)
    else:
        opts.lmhash, opts.nthash = '', opts.hashes

    if opts.aes_key:
        opts.kerberos = True

    if not opts.password and opts.user and not opts.hashes and not opts.no_pass and not opts.aeskey:
        from getpass import getpass
        opts.password = getpass('password:')

    if opts.category:
        opts.indicators = {type: [product for product in products if product['category'] == opts.category] for type, products in indicators.items()}
    else:
        opts.indicators = indicators

    successes, failures = 0, 0
    with ThreadPoolExecutor(max_workers=opts.threads) as pool:
        for result in pool.map(functools.partial(run_detections, opts=opts), opts.hosts):
            if result:
                successes += 1
            else:
                failures += 1
    exit(1 if failures else 0)


if __name__ == '__main__':
    main()
