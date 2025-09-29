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

parser_list = subparsers.add_parser("list", help="domain(s) list")

# Add

parser_add_a = subparsers.add_parser("add_a", help="domain add A record")
parser_add_a.add_argument("domain_id", type=int, help="Domain ID")
parser_add_a.add_argument("dns_name", type=str, help="DNS name")
parser_add_a.add_argument("ip_address", type=str, help="IP address")
parser_add_a.add_argument("--ttl", type=int, help="TTL", required=False, default=3600)

parser_add_aaaa = subparsers.add_parser("add_aaaa", help="domain add AAAA record")
parser_add_aaaa.add_argument("domain_id", type=int, help="Domain ID")
parser_add_aaaa.add_argument("dns_name", type=str, help="DNS name")
parser_add_aaaa.add_argument("ipv6_address", type=str, help="IPv6 address")
parser_add_aaaa.add_argument("--ttl", type=int, help="TTL", required=False, default=3600)

parser_add_mx = subparsers.add_parser("add_mx", help="domain add MX record")
parser_add_mx.add_argument("domain_id", type=int, help="Domain ID")
parser_add_mx.add_argument("dns_name", type=str, help="DNS name")
parser_add_mx.add_argument("ms_server", type=str, help="MX server")
parser_add_mx.add_argument("priority", type=int, help="Priority")
parser_add_mx.add_argument("--ttl", type=int, help="TTL", required=False, default=3600)

parser_add_srv = subparsers.add_parser("add_srv", help="domain add SRV record")
parser_add_srv.add_argument("domain_id", type=int, help="Domain ID")
parser_add_srv.add_argument("priority", type=int, help="Priority")
parser_add_srv.add_argument("host", type=str, help="Host")
parser_add_srv.add_argument("--ttl", type=int, help="TTL", required=False, default=3600)
parser_add_srv.add_argument("srv_priority", type=int, help="SRV priority")
parser_add_srv.add_argument("weight", type=int, help="Weight")
parser_add_srv.add_argument("port", type=int, help="Port")
parser_add_srv.add_argument("address", type=str, help="Address")

parser_add_cname = subparsers.add_parser("add_cname", help="domain add CNAME record")
parser_add_cname.add_argument("domain_id", type=int, help="Domain ID")
parser_add_cname.add_argument("dns_name", type=str, help="DNS name")
parser_add_cname.add_argument("sub_domain", type=str, help="Subdomain")
parser_add_cname.add_argument("--ttl", type=int, help="TTL", required=False, default=3600)

parser_add_txt = subparsers.add_parser("add_txt", help="domain add TXT record")
parser_add_txt.add_argument("domain_id", type=int, help="Domain ID")
parser_add_txt.add_argument("dns_name", type=str, help="DNS name")
parser_add_txt.add_argument("txt_record", type=str, help="TXT record")
parser_add_txt.add_argument("--ttl", type=int, help="TTL", required=False, default=3600)

parser_add_ns = subparsers.add_parser("add_ns", help="domain add NS record")
parser_add_ns.add_argument("domain_id", type=int, help="Domain ID")
parser_add_ns.add_argument("ns_name", type=str, help="NS name")
parser_add_ns.add_argument("ns_field", type=str, help="NS field")
parser_add_ns.add_argument("--ttl", type=int, help="TTL", required=False, default=3600)

# Get

parser_get = subparsers.add_parser("get", help="domain get records")
parser_get.add_argument("domain_id", type=int, help="Domain ID")

# Edit

parser_edit_a = subparsers.add_parser("edit_a", help="domain edit A record")
parser_edit_a.add_argument("record_id", type=str, help="Record ID")
parser_edit_a.add_argument("domain_id", type=int, help="Domain ID")
parser_edit_a.add_argument("dns_name", type=str, help="DNS name")
parser_edit_a.add_argument("ip_address", type=str, help="IP address")
parser_edit_a.add_argument("--ttl", type=int, help="TTL", required=False, default=3600)

parser_edit_aaaa = subparsers.add_parser("edit_aaaa", help="domain edit AAAA record")
parser_edit_aaaa.add_argument("record_id", type=str, help="Record ID")
parser_edit_aaaa.add_argument("domain_id", type=int, help="Domain ID")
parser_edit_aaaa.add_argument("dns_name", type=str, help="DNS name")
parser_edit_aaaa.add_argument("ipv6_address", type=str, help="IPv6 address")
parser_edit_aaaa.add_argument("--ttl", type=int, help="TTL", required=False, default=3600)

parser_edit_mx = subparsers.add_parser("edit_mx", help="domain edit MX record")
parser_edit_mx.add_argument("record_id", type=str, help="Record ID")
parser_edit_mx.add_argument("domain_id", type=int, help="Domain ID")
parser_edit_mx.add_argument("dns_name", type=str, help="DNS name")
parser_edit_mx.add_argument("ms_server", type=str, help="MX server")
parser_edit_mx.add_argument("priority", type=int, help="Priority")
parser_edit_mx.add_argument("--ttl", type=int, help="TTL", required=False, default=3600)

parser_edit_srv = subparsers.add_parser("edit_srv", help="domain edit SRV record")
parser_edit_srv.add_argument("record_id", type=str, help="Record ID")
parser_edit_srv.add_argument("domain_id", type=int, help="Domain ID")
parser_edit_srv.add_argument("priority", type=int, help="Priority")
parser_edit_srv.add_argument("host", type=str, help="Host")
parser_edit_srv.add_argument("--ttl", type=int, help="TTL", required=False, default=3600)
parser_edit_srv.add_argument("srv_priority", type=int, help="SRV priority")
parser_edit_srv.add_argument("weight", type=int, help="Weight")
parser_edit_srv.add_argument("port", type=int, help="Port")
parser_edit_srv.add_argument("address", type=str, help="Address")

parser_edit_cname = subparsers.add_parser("edit_cname", help="domain edit CNAME record")
parser_edit_cname.add_argument("record_id", type=str, help="Record ID")
parser_edit_cname.add_argument("domain_id", type=int, help="Domain ID")
parser_edit_cname.add_argument("dns_name", type=str, help="DNS name")
parser_edit_cname.add_argument("sub_domain", type=str, help="Subdomain")
parser_edit_cname.add_argument("--ttl", type=int, help="TTL", required=False, default=3600)

parser_edit_txt = subparsers.add_parser("edit_txt", help="domain edit TXT record")
parser_edit_txt.add_argument("record_id", type=str, help="Record ID")
parser_edit_txt.add_argument("domain_id", type=int, help="Domain ID")
parser_edit_txt.add_argument("dns_name", type=str, help="DNS name")
parser_edit_txt.add_argument("txt_record", type=str, help="TXT record")
parser_edit_txt.add_argument("--ttl", type=int, help="TTL", required=False, default=3600)

parser_edit_ns = subparsers.add_parser("edit_ns", help="domain edit NS record")
parser_edit_ns.add_argument("record_id", type=str, help="Record ID")
parser_edit_ns.add_argument("domain_id", type=int, help="Domain ID")
parser_edit_ns.add_argument("ns_name", type=str, help="NS name")
parser_edit_ns.add_argument("ns_field", type=str, help="NS field")
parser_edit_ns.add_argument("--ttl", type=int, help="TTL", required=False, default=3600)

# Delete

parser_delete = subparsers.add_parser("delete", help="domain delete record")
parser_delete.add_argument("record_id", type=str, help="Record ID")
parser_delete.add_argument("domain_id", type=int, help="Domain ID")

# DNS

parser_dns = subparsers.add_parser("dns", help="DNS auto settings")
parser_dns.add_argument("domain_id", type=int, help="Domain ID")

# DNSSEC

parser_dnssec = subparsers.add_parser("dnssec", help="get DNSSEC key")
parser_dnssec.add_argument("domain_id", type=int, help="Domain ID")

# DNSSEC enable

parser_dnssec_enable = subparsers.add_parser("dnssec_enable", help="DNSSEC enable")
parser_dnssec_enable.add_argument("domain_id", type=int, help="Domain ID")
parser_dnssec_enable.add_argument("dns_to_add", type=str, help="DNS to add")
parser_dnssec_enable.add_argument("ds_to_add", type=str, help="DS to add")

# SOA

parser_soa = subparsers.add_parser("soa", help="edit SOA")
parser_soa.add_argument("domain_id", type=int, help="Domain ID")
parser_soa.add_argument("dns_name", type=str, help="DNS name")
parser_soa.add_argument("email", type=str, help="Email")
parser_soa.add_argument("refresh", type=bool, help="Refresh")
parser_soa.add_argument("retry", type=int, help="Retry")
parser_soa.add_argument("expire", type=int, help="Expire")
parser_soa.add_argument("minimum", type=int, help="Minimum")
parser_soa.add_argument("ttl", type=int, help="TTL")

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

if args.function == "add_a":
    result = atex.domain_add_record_a(args.domain_id,
                                      args.dns_name,
                                      args.ip_address,
                                      args.ttl,
                                      login,
                                      password)
    print(result)
    exit(0)

if args.function == "add_aaaa":
    result = atex.domain_add_record_aaaa(args.domain_id,
                                         args.dns_name,
                                         args.ipv6_address,
                                         args.ttl,
                                         login, password)
    exit(0)

if args.function == "add_mx":
    result = atex.domain_add_record_mx(args.domain_id,
                                       args.dns_name,
                                       args.mx_server,
                                       args.priority,
                                       args.ttl,
                                       login,
                                       password)
    print(result)
    exit(0)

if args.function == "add_srv":
    result = atex.domain_add_record_srv(args.domain_id,
                                        args.priority,
                                        args.ttl,
                                        args.host,
                                        args.srv_priority,
                                        args.weight,
                                        args.port,
                                        args.address,
                                        login,
                                        password)
    print(result)
    exit(0)

if args.function == "add_cname":
    result = atex.domain_add_record_cname(args.domain_id,
                                          args.dns_name,
                                          args.sub_domain,
                                          args.ttl,
                                          login,
                                          password)
    print(result)
    exit(0)

if args.function == "add_txt":
    result = atex.domain_add_record_txt(args.domain_id,
                                        args.dns_name,
                                        args.txt_record,
                                        args.ttl,
                                        login,
                                        password)
    print(result)
    exit(0)

if args.function == "add_ns":
    result = atex.domain_add_record_ns(args.domain_id,
                                       args.ns_name,
                                       args.ns_field,
                                       args.ttl,
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

if args.function == "edit_a":
    result = atex.domain_edit_record_a(args.record_id,
                                       args.domain_id,
                                       args.dns_name,
                                       args.ip_address,
                                       args.ttl,
                                       login,
                                       password)
    print(result)
    exit(0)

if args.function == "edit_aaaa":
    result = atex.domain_edit_record_aaaa(args.record_id,
                                          args.domain_id,
                                          args.dns_name,
                                          args.ipv6_address,
                                          args.ttl,
                                          login, password)
    print(result)
    exit(0)

if args.function == "edit_mx":
    result = atex.domain_edit_record_mx(args.record_id,
                                        args.domain_id,
                                        args.dns_name,
                                        args.mx_server,
                                        args.priority,
                                        args.ttl,
                                        login,
                                        password)
    print(result)
    exit(0)

if args.function == "edit_srv":
    result = atex.domain_edit_record_srv(args.record_id,
                                         args.domain_id,
                                         args.priority,
                                         args.ttl,
                                         args.host,
                                         args.srv_priority,
                                         args.weight,
                                         args.port,
                                         args.address,
                                         login,
                                         password)
    print(result)
    exit(0)

if args.function == "edit_cname":
    result = atex.domain_edit_record_cname(args.record_id,
                                           args.domain_id,
                                           args.dns_name,
                                           args.sub_domain,
                                           args.ttl,
                                           login,
                                           password)
    print(result)
    exit(0)

if args.function == "edit_txt":
    result = atex.domain_edit_record_txt(args.record_id,
                                         args.domain_id,
                                         args.dns_name,
                                         args.txt_record,
                                         args.ttl,
                                         login,
                                         password)
    print(result)
    exit(0)

if args.function == "edit_ns":
    result = atex.domain_edit_record_ns(args.record_id,
                                        args.domain_id,
                                        args.ns_name,
                                        args.ns_field,
                                        args.ttl,
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
