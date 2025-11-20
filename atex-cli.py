import argparse
import os

from tabulate import tabulate

import atex

parser = argparse.ArgumentParser(
    prog='atex-cli',
    description='Atex.ru command line tools.',
    epilog='Report bugs to lessavin@hotmail.com.')

# Login argument
parser.add_argument('--login',
                    help='atex login',
                    type=str,
                    required=False,
                    default=None)

# Password argument
parser.add_argument('--password',
                    help='atex password',
                    type=str,
                    required=False,
                    default=None)

subparsers = parser.add_subparsers(dest="function")

# List

list_function_p = subparsers.add_parser('list', help='domain(s) list')

# Add

add_function_p = subparsers.add_parser('add', help='domain add record')
add_function_sp = add_function_p.add_subparsers(help='Method to perform', dest='add')

# Add A

a_add_function_p = add_function_sp.add_parser('a', help='domain add A record')
a_add_function_p.add_argument("domain_id", type=int, help="Domain ID")
a_add_function_p.add_argument("dns_name", type=str, help="DNS name")
a_add_function_p.add_argument("ip_address", type=str, help="IP address")

# Add AAAA

aaaa_add_function_p = add_function_sp.add_parser('aaaa', help='domain add AAAA record')
aaaa_add_function_p.add_argument("domain_id", type=int, help="Domain ID")
aaaa_add_function_p.add_argument("dns_name", type=str, help="DNS name")
aaaa_add_function_p.add_argument("ipv6_address", type=str, help="IPv6 address")

# Add MX

mx_add_function_p = add_function_sp.add_parser('mx', help='domain add MX record')
mx_add_function_p.add_argument("domain_id", type=int, help="Domain ID")
mx_add_function_p.add_argument("dns_name", type=str, help="DNS name")
mx_add_function_p.add_argument("ms_server", type=str, help="MX server")
mx_add_function_p.add_argument("priority", type=int, help="Priority")

# Add SRV

srv_add_function_p = add_function_sp.add_parser('srv', help='domain add SRV record')
srv_add_function_p.add_argument("domain_id", type=int, help="Domain ID")
srv_add_function_p.add_argument("priority", type=int, help="Priority")
srv_add_function_p.add_argument("host", type=str, help="Host")
srv_add_function_p.add_argument("srv_priority", type=int, help="SRV priority")
srv_add_function_p.add_argument("weight", type=int, help="Weight")
srv_add_function_p.add_argument("port", type=int, help="Port")
srv_add_function_p.add_argument("address", type=str, help="Address")

# Add CNAME

cname_add_function_p = add_function_sp.add_parser('cname', help='domain add CNAME record')
cname_add_function_p.add_argument("domain_id", type=int, help="Domain ID")
cname_add_function_p.add_argument("dns_name", type=str, help="DNS name")
cname_add_function_p.add_argument("sub_domain", type=str, help="Subdomain")

# Add TXT

txt_add_function_p = add_function_sp.add_parser('txt', help='domain add TXT record')
txt_add_function_p.add_argument("domain_id", type=int, help="Domain ID")
txt_add_function_p.add_argument("dns_name", type=str, help="DNS name")
txt_add_function_p.add_argument("txt_record", type=str, help="TXT record")

# Add NS

ns_add_function_p = add_function_sp.add_parser('ns', help='domain add NS record')
ns_add_function_p.add_argument("domain_id", type=int, help="Domain ID")
ns_add_function_p.add_argument("ns_name", type=str, help="NS name")
ns_add_function_p.add_argument("ns_field", type=str, help="NS field")

# Get

get_function_p = subparsers.add_parser('get', help='domain get records')
get_function_p.add_argument("domain_id", type=int, help="Domain ID")

# Edit

edit_function_p = subparsers.add_parser('edit', help='domain edit record')
edit_function_sp = edit_function_p.add_subparsers(help='Method to perform', dest='edit')

# Edit A

a_edit_function_p = edit_function_sp.add_parser('a', help='domain add A record')
a_edit_function_p.add_argument("domain_id", type=int, help="Domain ID")
a_edit_function_p.add_argument("dns_name", type=str, help="DNS name")
a_edit_function_p.add_argument("ip_address", type=str, help="IP address")

# Edit AAAA

aaaa_edit_function_p = edit_function_sp.add_parser('aaaa', help='domain add AAAA record')
aaaa_edit_function_p.add_argument("domain_id", type=int, help="Domain ID")
aaaa_edit_function_p.add_argument("dns_name", type=str, help="DNS name")
aaaa_edit_function_p.add_argument("ipv6_address", type=str, help="IPv6 address")

# Edit MX

mx_edit_function_p = edit_function_sp.add_parser('mx', help='domain add MX record')
mx_edit_function_p.add_argument("domain_id", type=int, help="Domain ID")
mx_edit_function_p.add_argument("dns_name", type=str, help="DNS name")
mx_edit_function_p.add_argument("ms_server", type=str, help="MX server")
mx_edit_function_p.add_argument("priority", type=int, help="Priority")

# Edit SRV

srv_edit_function_p = edit_function_sp.add_parser('srv', help='domain add SRV record')
srv_edit_function_p.add_argument("domain_id", type=int, help="Domain ID")
srv_edit_function_p.add_argument("priority", type=int, help="Priority")
srv_edit_function_p.add_argument("host", type=str, help="Host")
srv_edit_function_p.add_argument("srv_priority", type=int, help="SRV priority")
srv_edit_function_p.add_argument("weight", type=int, help="Weight")
srv_edit_function_p.add_argument("port", type=int, help="Port")
srv_edit_function_p.add_argument("address", type=str, help="Address")

# Edit CNAME

cname_edit_function_p = edit_function_sp.add_parser('cname', help='domain add CNAME record')
cname_edit_function_p.add_argument("domain_id", type=int, help="Domain ID")
cname_edit_function_p.add_argument("dns_name", type=str, help="DNS name")
cname_edit_function_p.add_argument("sub_domain", type=str, help="Subdomain")

# Edit TXT

txt_edit_function_p = edit_function_sp.add_parser('txt', help='domain add TXT record')
txt_edit_function_p.add_argument("domain_id", type=int, help="Domain ID")
txt_edit_function_p.add_argument("dns_name", type=str, help="DNS name")
txt_edit_function_p.add_argument("txt_record", type=str, help="TXT record")

# Edit NS

ns_edit_function_p = edit_function_sp.add_parser('ns', help='domain add NS record')
ns_edit_function_p.add_argument("domain_id", type=int, help="Domain ID")
ns_edit_function_p.add_argument("ns_name", type=str, help="NS name")
ns_edit_function_p.add_argument("ns_field", type=str, help="NS field")

# Delete

delete_function_p = subparsers.add_parser('delete', help='domain delete record')
delete_function_p.add_argument("record_id", type=str, help="Record ID")
delete_function_p.add_argument("domain_id", type=int, help="Domain ID")

# DNS

dns_function_p = subparsers.add_parser('dns', help='DNS auto settings')
dns_function_p.add_argument("domain_id", type=int, help="Domain ID")

# DNSSEC

dnssec_function_p = subparsers.add_parser('dnssec', help='get DNSSEC key')
dnssec_function_p.add_argument("domain_id", type=int, help="Domain ID")

# DNSSEC enable

dnssec_enable_function_p = subparsers.add_parser('dnssec-enable', help='DNSSEC enable')
dnssec_enable_function_p.add_argument("domain_id", type=int, help="Domain ID")
dnssec_enable_function_p.add_argument("dns_to_add", type=str, help="DNS to add")
dnssec_enable_function_p.add_argument("ds_to_add", type=str, help="DS to add")

# SOA

soa_function_p = subparsers.add_parser('soa', help='edit SOA')
soa_function_p.add_argument("domain_id", type=int, help="Domain ID")
soa_function_p.add_argument("dns_name", type=str, help="DNS name")
soa_function_p.add_argument("email", type=str, help="Email")
soa_function_p.add_argument("refresh", type=bool, help="Refresh")
soa_function_p.add_argument("retry", type=int, help="Retry")
soa_function_p.add_argument("expire", type=int, help="Expire")
soa_function_p.add_argument("minimum", type=int, help="Minimum")
soa_function_p.add_argument("ttl", type=int, help="TTL")

args = parser.parse_args()

if args.function is None:
    parser.print_help()

# Setup authinfo
login = args.login
if login is None:
    login = os.environ.setdefault("ATEX_LOGIN", "")

password = args.password
if password is None:
    password = os.environ.setdefault("ATEX_PASSWORD", "")

if not (login and password):
    print("Login or password is missing or can't be accessed.")
    exit(1)

if args.function == "list":
    result = tabulate(atex.domain_list(login, password),
                      headers=["Id", "Domain name", "Tariff plan", "End date", "DNS", "Status", "Price"],
                      tablefmt="plain")
    print(result)
    exit(0)

if args.function == "add":
    result = "dns_type not found."

    if args.add == "a":
        result = atex.domain_add_record_a(args.domain_id,
                                          args.dns_name,
                                          args.ip_address,
                                          login,
                                          password)
        print(result)
        exit(0)

    if args.add == "aaaa":
        result = atex.domain_add_record_aaaa(args.domain_id,
                                             args.dns_name,
                                             args.ipv6_address,
                                             login,
                                             password)
        print(result)
        exit(0)

    if args.add == "mx":
         result = atex.domain_add_record_mx(args.domain_id,
                                            args.dns_name,
                                            args.mx_server,
                                            args.priority,
                                            login,
                                            password)
         print(result)
         exit(0)

    if args.add == "srv":
         result = atex.domain_add_record_srv(args.domain_id,
                                             args.priority,
                                             args.host,
                                             args.srv_priority,
                                             args.weight,
                                             args.port,
                                             args.address,
                                             login,
                                             password)
         print(result)
         exit(0)

    if args.add == "cname":
         result = atex.domain_add_record_cname(args.domain_id,
                                               args.dns_name,
                                               args.sub_domain,
                                               login,
                                               password)
         print(result)
         exit(0)

    if args.add == "txt":
         result = atex.domain_add_record_txt(args.domain_id,
                                             args.dns_name,
                                             args.txt_record,
                                             login,
                                             password)
         print(result)
         exit(0)

    if args.add == "ns":
         result = atex.domain_add_record_ns(args.domain_id,
                                            args.ns_name,
                                            args.ns_field,
                                            login,
                                            password)
         print(result)
         exit(0)

if args.function == "get":
    result = tabulate(atex.domain_get_records(args.domain_id, login, password),
                      headers=["ID", "Host", "TTL", "Record type", "Content"],
                      tablefmt="plain")
    print(result)
    exit(0)

if args.function == "edit":
    result = "dns_type not found."

    if args.edit == "a":
        result = atex.domain_edit_record_a(args.record_id,
                                           args.domain_id,
                                           args.dns_name,
                                           args.ip_address,
                                           login,
                                           password)
        print(result)
        exit(0)

    if args.edit == "aaaa":
        result = atex.domain_edit_record_aaaa(args.record_id,
                                              args.domain_id,
                                              args.dns_name,
                                              args.ipv6_address,
                                              login,
                                              password)
        print(result)
        exit(0)

    if args.edit == "mx":
        result = atex.domain_edit_record_mx(args.record_id,
                                            args.domain_id,
                                            args.dns_name,
                                            args.mx_server,
                                            args.priority,
                                            login,
                                            password)
        print(result)
        exit(0)

    if args.edit == "srv":
        result = atex.domain_edit_record_srv(args.record_id,
                                             args.domain_id,
                                             args.priority,
                                             args.host,
                                             args.srv_priority,
                                             args.weight,
                                             args.port,
                                             args.address,
                                             login,
                                             password)
        print(result)
        exit(0)

    if args.edit == "cname":
        result = atex.domain_edit_record_cname(args.record_id,
                                               args.domain_id,
                                               args.dns_name,
                                               args.sub_domain,
                                               login,
                                               password)
        print(result)
        exit(0)

    if args.edit == "txt":
        result = atex.domain_edit_record_txt(args.record_id,
                                             args.domain_id,
                                             args.dns_name,
                                             args.txt_record,
                                             login,
                                             password)
        print(result)
        exit(0)

    if args.edit == "ns":
        result = atex.domain_edit_record_ns(args.record_id,
                                            args.domain_id,
                                            args.ns_name,
                                            args.ns_field,
                                            login,
                                            password)
        print(result)
        exit(0)

if args.function == "delete":
    result = atex.domain_delete_record(args.record_id,
                                       args.domain_id,
                                       login,
                                       password)
    print(result)
    exit(0)

if args.function == "dns":
    result = atex.dns_auto_settings(args.domain_id,
                                    login,
                                    password)
    print(result)
    exit(0)

if args.function == "dnssec":
    result = atex.dnssec_get(args.domain_id,
                             login,
                             password)
    print(result)
    exit(0)

if args.function == "dnssec_enable":
    result = atex.dnssec_enable(args.domain_id,
                                args.dns_to_add,
                                args.ds_to_add,
                                login,
                                password)
    print(result)
    exit(0)

if args.function == "soa":
    result = atex.soa_edit(args.domain_id,
                           args.dns_name,
                           args.email,
                           args.refresh,
                           args.retry,
                           args.expire,
                           args.minimum,
                           args.ttl,
                           login,
                           password)
    print(result)
    exit(0)

parser.print_help()
