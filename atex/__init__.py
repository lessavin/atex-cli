import xml.dom.minidom
from typing import Any
from xml.etree import ElementTree

import requests


def domain_list(login: str,
                password: str) -> list[Any]:
    response = requests.get(domain_list_raw(login, password))
    root = ElementTree.fromstring(response.text)
    table = []

    for elem in root.findall("./elem"):
        table.append([elem.find("id").text,
                      elem.find("domain").text,
                      elem.find("pricelist").text,
                      elem.find("expiredate").text,
                      elem.find("nslist").text,
                      elem.find("status").text,
                      elem.find("cost").text])

    return table


def domain_list_raw(login: str,
                    password: str) -> str:
    return f"https://my.atex.ru/billmgr?func=domain&out=xml&authinfo={login}:{password}"


def domain_add_record_a(domain_id: int,
                        dns_name: str,
                        ip_address: str,
                        ttl: int,
                        login: str,
                        password: str) -> str:
    response = requests.get(domain_add_record_a_raw(domain_id, dns_name, ip_address, ttl, login, password))
    return pretty_xml_as_string(response.text)


def domain_add_record_a_raw(domain_id: int,
                            dns_name: str,
                            ip_address: str,
                            ttl: int,
                            login: str,
                            password: str) -> str:
    return f"https://my.atex.ru/billmgr?plid={domain_id}&func=domain.dnsrecords.edit&dns_type=A&dns_name={dns_name}&ipv4={ip_address}&ttl={ttl}&sok=ok&clicked_button=ok&authinfo={login}:{password}&out=xml"


def domain_add_record_aaaa(domain_id: int,
                           dns_name: str,
                           ipv6_address: str,
                           ttl: int,
                           login: str,
                           password: str) -> str:
    response = requests.get(domain_add_record_aaaa_raw(domain_id, dns_name, ipv6_address, ttl, login, password))
    return pretty_xml_as_string(response.text)


def domain_add_record_aaaa_raw(domain_id: int,
                               dns_name: str,
                               ipv6_address: str,
                               ttl: int,
                               login: str,
                               password: str) -> str:
    return f"https://my.atex.ru/billmgr?plid={domain_id}&func=domain.dnsrecords.edit&dns_type=AAAA&dns_name={dns_name}&ipv6={ipv6_address}&ttl={ttl}&sok=ok&clicked_button=ok&authinfo={login}:{password}&out=xml"


def domain_add_record_mx(domain_id: int,
                         dns_name: str,
                         mx_server: str,
                         priority: int,
                         ttl: int,
                         login: str,
                         password: str) -> str:
    response = requests.get(domain_add_record_mx_raw(domain_id, dns_name, mx_server, priority, ttl, login, password))
    return pretty_xml_as_string(response.text)


def domain_add_record_mx_raw(domain_id: int,
                             dns_name: str,
                             mx_server: str,
                             priority: int,
                             ttl: int,
                             login: str,
                             password: str) -> str:
    return f"https://my.atex.ru/billmgr?plid={domain_id}&func=domain.dnsrecords.edit&dns_type=MX&dns_name={dns_name}&mx={mx_server}&priority={priority}&ttl={ttl}&sok=ok&clicked_button=ok&authinfo={login}:{password}&out=xml"


def domain_add_record_srv(domain_id: int,
                          priority: int,
                          ttl: int,
                          host: str,
                          srv_priority: int,
                          weight: int,
                          port: int,
                          address: str,
                          login: str,
                          password: str) -> str:
    response = requests.get(
        domain_add_record_srv_raw(domain_id, priority, ttl, host, srv_priority, weight, port, address, login, password))
    return pretty_xml_as_string(response.text)


def domain_add_record_srv_raw(domain_id: int,
                              priority: int,
                              ttl: int,
                              host: str,
                              srv_priority: int,
                              weight: int,
                              port: int,
                              address: str,
                              login: str,
                              password: str) -> str:
    return f"https://my.atex.ru/billmgr?plid={domain_id}&func=domain.dnsrecords.edit&dns_type=SRV&priority={priority}&ttl={ttl}&dns_name_srv={host}&srv_priority={srv_priority}&weight={weight}&port={port}&address={address}&sok=ok&clicked_button=ok&authinfo={login}:{password}&out=xml"


def domain_add_record_cname(domain_id: int,
                            dns_name: str,
                            sub_domain: str,
                            ttl: int,
                            login: str,
                            password: str) -> str:
    response = requests.get(domain_add_record_cname_raw(domain_id, dns_name, sub_domain, ttl, login, password))
    return pretty_xml_as_string(response.text)


def domain_add_record_cname_raw(domain_id: int,
                                dns_name: str,
                                sub_domain: str,
                                ttl: int,
                                login: str,
                                password: str) -> str:
    return f"https://my.atex.ru/billmgr?plid={domain_id}&func=domain.dnsrecords.edit&dns_type=CNAME&dns_name={dns_name}&canonical_name={sub_domain}&ttl={ttl}&sok=ok&clicked_button=ok&authinfo={login}:{password}&out=xml"


def domain_add_record_txt(domain_id: int,
                          dns_name: str,
                          txt_record: str,
                          ttl: int,
                          login: str,
                          password: str) -> str:
    response = requests.get(domain_add_record_txt_raw(domain_id, dns_name, txt_record, ttl, login, password))
    return pretty_xml_as_string(response.text)


def domain_add_record_txt_raw(domain_id: int,
                              dns_name: str,
                              txt_record: str,
                              ttl: int,
                              login: str,
                              password: str) -> str:
    return f"https://my.atex.ru/billmgr?plid={domain_id}&func=domain.dnsrecords.edit&dns_type=TXT&dns_name={dns_name}&txt={txt_record}&ttl={ttl}&sok=ok&clicked_button=ok&authinfo={login}:{password}&out=xml"


def domain_add_record_ns(domain_id: int,
                         ns_name: str,
                         ns_field: str,
                         ttl: int,
                         login: str,
                         password: str) -> str:
    response = requests.get(domain_add_record_ns_raw(domain_id, ns_name, ns_field, ttl, login, password))
    return pretty_xml_as_string(response.text)


def domain_add_record_ns_raw(domain_id: int,
                             ns_name: str,
                             ns_field: str,
                             ttl: int,
                             login: str,
                             password: str) -> str:
    return f"https://my.atex.ru/billmgr?plid={domain_id}&func=domain.dnsrecords.edit&dns_type=NS&ns_name={ns_name}&ns_field={ns_field}&ttl={ttl}&sok=ok&clicked_button=ok&authinfo={login}:{password}&out=xml"


def domain_get_records(domain_id: int,
                       login: str,
                       password: str) -> list[Any]:
    response = requests.get(domain_get_records_raw(domain_id, login, password))
    root = ElementTree.fromstring(response.text)
    table = []

    for elem in root.findall("./elem"):
        table.append([elem.find("dns_id").text,
                      elem.find("dns_name").text,
                      elem.find("dns_ttl").text,
                      elem.find("dns_type").text,
                      elem.find("dns_content").text])

    return table


def domain_get_records_raw(domain_id: int,
                           login: str,
                           password: str):
    return f"https://my.atex.ru/billmgr?elid={domain_id}&func=domain.dnsrecords&out=xml&authinfo={login}:{password}"


def domain_edit_record_a(record_id: str,
                         domain_id: int,
                         dns_name: str,
                         ip_address: str,
                         ttl: int,
                         login: str,
                         password: str) -> str:
    response = requests.get(domain_edit_record_a_raw(record_id, domain_id, dns_name, ip_address, ttl, login, password))
    return pretty_xml_as_string(response.text)


def domain_edit_record_a_raw(record_id: str,
                             domain_id: int,
                             dns_name: str,
                             ip_address: str,
                             ttl: int,
                             login: str,
                             password: str) -> str:
    return f"https://my.atex.ru/billmgr?elid={record_id}&plid={domain_id}&func=domain.dnsrecords.edit&out=xml&authinfo={login}:{password}&dns_type=A&dns_name={dns_name}&ipv4={ip_address}&clicked_button=ok&sok=ok&ttl={ttl}"


def domain_edit_record_aaaa(record_id: str,
                            domain_id: int,
                            dns_name: str,
                            ipv6_address: str,
                            ttl: int,
                            login: str,
                            password: str) -> str:
    response = requests.get(
        domain_edit_record_aaaa_raw(record_id, domain_id, dns_name, ipv6_address, ttl, login, password))
    return pretty_xml_as_string(response.text)


def domain_edit_record_aaaa_raw(record_id: str,
                                domain_id: int,
                                dns_name: str,
                                ipv6_address: str,
                                ttl: int,
                                login: str,
                                password: str) -> str:
    return f"https://my.atex.ru/billmgr?elid={record_id}?plid={domain_id}&func=domain.dnsrecords.edit&dns_type=AAAA&dns_name={dns_name}&ipv6={ipv6_address}&ttl={ttl}&sok=ok&clicked_button=ok&authinfo={login}:{password}&out=xml"


def domain_edit_record_mx(record_id: str,
                          domain_id: int,
                          dns_name: str,
                          mx_server: str,
                          priority: int,
                          ttl: int,
                          login: str,
                          password: str) -> str:
    response = requests.get(
        domain_edit_record_mx_raw(record_id, domain_id, dns_name, mx_server, ttl, priority, login, password))
    return pretty_xml_as_string(response.text)


def domain_edit_record_mx_raw(record_id: str,
                              domain_id: int,
                              dns_name: str,
                              mx_server: str,
                              priority: int,
                              ttl: int,
                              login: str,
                              password: str) -> str:
    return f"https://my.atex.ru/billmgr?elid={record_id}?plid={domain_id}&func=domain.dnsrecords.edit&dns_type=MX&dns_name={dns_name}&mx={mx_server}&priority={priority}&ttl={ttl}&sok=ok&clicked_button=ok&authinfo={login}:{password}&out=xml"


def domain_edit_record_srv(record_id: str,
                           domain_id: int,
                           priority: int,
                           ttl: int,
                           host: str,
                           srv_priority: int,
                           weight: int,
                           port: int,
                           address: str,
                           login: str,
                           password: str) -> str:
    response = requests.get(
        domain_edit_record_srv_raw(record_id, domain_id, priority, ttl, host, srv_priority, weight, port, address,
                                   login,
                                   password))
    return pretty_xml_as_string(response.text)


def domain_edit_record_srv_raw(record_id: str,
                               domain_id: int,
                               priority: int,
                               ttl: int,
                               host: str,
                               srv_priority: int,
                               weight: int,
                               port: int,
                               address: str,
                               login: str,
                               password: str) -> str:
    return f"https://my.atex.ru/billmgr?elid={record_id}?plid={domain_id}&func=domain.dnsrecords.edit&dns_type=SRV&priority={priority}&ttl={ttl}&dns_name_srv={host}&srv_priority={srv_priority}&weight={weight}&port={port}&address={address}&sok=ok&clicked_button=ok&authinfo={login}:{password}&out=xml"


def domain_edit_record_cname(record_id: str,
                             domain_id: int,
                             dns_name: str,
                             sub_domain: str,
                             ttl: int,
                             login: str,
                             password: str) -> str:
    response = requests.get(
        domain_edit_record_cname_raw(record_id, domain_id, dns_name, sub_domain, ttl, login, password))
    return pretty_xml_as_string(response.text)


def domain_edit_record_cname_raw(record_id: str,
                                 domain_id: int,
                                 dns_name: str,
                                 sub_domain: str,
                                 ttl: int,
                                 login: str,
                                 password: str) -> str:
    return f"https://my.atex.ru/billmgr?elid={record_id}?plid={domain_id}&func=domain.dnsrecords.edit&dns_type=CNAME&dns_name={dns_name}&canonical_name={sub_domain}&ttl={ttl}&sok=ok&clicked_button=ok&authinfo={login}:{password}&out=xml"


def domain_edit_record_txt(record_id: str,
                           domain_id: int,
                           dns_name: str,
                           txt_record: str,
                           ttl: int,
                           login: str,
                           password: str) -> str:
    response = requests.get(
        domain_edit_record_txt_raw(record_id, domain_id, dns_name, txt_record, ttl, login, password))
    return pretty_xml_as_string(response.text)


def domain_edit_record_txt_raw(record_id: str,
                               domain_id: int,
                               dns_name: str,
                               txt_record: str,
                               ttl: int,
                               login: str,
                               password: str) -> str:
    return f"https://my.atex.ru/billmgr?elid={record_id}?plid={domain_id}&func=domain.dnsrecords.edit&dns_type=TXT&dns_name={dns_name}&txt={txt_record}&ttl={ttl}&sok=ok&clicked_button=ok&authinfo={login}:{password}&out=xml"


def domain_edit_record_ns(record_id: str,
                          domain_id: int,
                          ns_name: str,
                          ns_field: str,
                          ttl: int,
                          login: str,
                          password: str) -> str:
    response = requests.get(domain_edit_record_ns_raw(record_id, domain_id, ns_name, ns_field, ttl, login, password))
    return pretty_xml_as_string(response.text)


def domain_edit_record_ns_raw(record_id: str,
                              domain_id: int,
                              ns_name: str,
                              ns_field: str,
                              ttl: int,
                              login: str,
                              password: str) -> str:
    return f"https://my.atex.ru/billmgr?elid={record_id}?plid={domain_id}&func=domain.dnsrecords.edit&dns_type=NS&ns_name={ns_name}&ns_field={ns_field}&ttl={ttl}&sok=ok&clicked_button=ok&authinfo={login}:{password}&out=xml"


def domain_delete_record(record_id: str,
                         domain_id: int,
                         login: str,
                         password: str) -> str:
    response = requests.get(domain_delete_record_raw(record_id, domain_id, login, password))
    return pretty_xml_as_string(response.text)


def domain_delete_record_raw(record_id: str,
                             domain_id: int,
                             login: str,
                             password: str) -> str:
    return f"https://my.atex.ru/billmgr?elid={record_id}&func=domain.dnsrecords.delete&plid={domain_id}&out=xml&authinfo={login}:{password}"


def dns_auto_settings(domain_id: int,
                      login: str,
                      password: str) -> str:
    response = requests.get(dns_auto_settings_raw(domain_id, login, password))
    return pretty_xml_as_string(response.text)


def dns_auto_settings_raw(domain_id: int,
                          login: str,
                          password: str) -> str:
    return f"https://my.atex.ru/billmgr?func=domain.dnsrecords.autoconfigns&elid={domain_id}&out=xml&authinfo={login}:{password}&clicked_button=ok&sok=ok"


def dnssec_get(domain_id: int,
               login: str,
               password: str) -> str:
    response = requests.get(dnssec_get_raw(domain_id, login, password))
    return pretty_xml_as_string(response.text)


def dnssec_get_raw(domain_id: int,
                   login: str,
                   password: str) -> str:
    return f"https://my.atex.ru/billmgr?plid={domain_id}&func=domain.dnsrecords.dnssec&out=xml&authinfo={login}:{password}"


def dnssec_enable(domain_id: int,
                  dns_to_add: str,
                  ds_to_add: str,
                  login: str,
                  password: str) -> str:
    response = requests.get(dnssec_enable_raw(domain_id, dns_to_add, ds_to_add, login, password))
    return pretty_xml_as_string(response.text)


def dnssec_enable_raw(domain_id: int,
                      dns_to_add: str,
                      ds_to_add: str,
                      login: str,
                      password: str) -> str:
    return f"https://my.atex.ru/billmgr?func=domain.dnsrecords.dnssec&plid={domain_id}&dns_to_add={dns_to_add}&ds_to_add={ds_to_add}&clicked_button=ok&sok=ok&out=xml&authinfo={login}:{password}"


def soa_edit(domain_id: int,
             dns_name: str,
             email: str,
             refresh: bool,
             retry: int,
             expire: int,
             minimum: int,
             ttl: int,
             login: str,
             password: str) -> str:
    return f"https://my.atex.ru/billmgr?func=domain.dnsrecords.editsoa&elid=&plid={domain_id}&dns_type=SOA&dns_name={dns_name}&email={email}&refresh={refresh}&retry={retry}&expire={expire}&minimum={minimum}&ttl={ttl}&clicked_button=ok&sok=ok&out=xml&authinfo={login}:{password}"


def soa_edit_raw(domain_id: int,
                 dns_name: str,
                 email: str,
                 refresh: bool,
                 retry: int,
                 expire: int,
                 minimum: int,
                 ttl: int,
                 login: str,
                 password: str) -> str:
    return f"https://my.atex.ru/billmgr?func=domain.dnsrecords.editsoa&elid=&plid={domain_id}&dns_type=SOA&dns_name={dns_name}&email={email}&refresh={refresh}&retry={retry}&expire={expire}&minimum={minimum}&ttl={ttl}&clicked_button=ok&sok=ok&out=xml&authinfo={login}:{password}"


# Make XML string prettier.
# Source: https://stackoverflow.com/a/1206856
def pretty_xml_as_string(xml_string: str) -> str:
    dom = xml.dom.minidom.parseString(xml_string)
    return dom.toprettyxml()
