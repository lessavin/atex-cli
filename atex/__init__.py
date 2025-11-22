import urllib.parse
import urllib.request
import xml.dom.minidom
from typing import Any
from xml.etree import ElementTree


class AtexRequest(dict):
    """
    Represents a general Atex request, inheriting from dict to allow dictionary-like access.
    """

    def __init__(self, authinfo, func):
        super().__init__()  # Initialize the dict base class

        self["authinfo"] = authinfo
        self["func"] = func
        self["out"] = "xml"

    def raw(self) -> str:
        return "https://my.atex.ru/billmgr?" + urllib.parse.urlencode(self)

    def send(self) -> str:
        with urllib.request.urlopen(self.raw()) as response:
            data = response.read()

            encoding = response.headers.get_content_charset()

            if encoding is None:
                encoding = "utf-8"

            result = data.decode(encoding)
        return result


class ListAtexRequest(AtexRequest):
    def __init__(self, authinfo):
        super().__init__(authinfo, "domain")


class RecordAtexRequest(AtexRequest):
    """
    Represents a DNS record Atex request.
    """

    def __init__(self, authinfo, func, dns_type, plid, ttl):
        super().__init__(authinfo, func)

        self["clicked_button"] = "ok"
        self["dns_type"] = dns_type
        self["plid"] = plid
        self["sok"] = "ok"
        self["ttl"] = ttl


class ARecordAtexRequest(RecordAtexRequest):
    def __init__(self, authinfo, plid, ttl, dns_name, ipv4):
        super().__init__(authinfo, "domain.dnsrecords.edit", "A", plid, ttl)

        self["dns_name"] = dns_name
        self["ipv4"] = ipv4


class EditARecordAtexRequest(ARecordAtexRequest):
    def __init__(self, authinfo, plid, ttl, dns_name, ipv4, elid):
        super().__init__(authinfo, plid, ttl, dns_name, ipv4)

        self["elid"] = elid


class AAAARecordAtexRequest(RecordAtexRequest):
    def __init__(self, authinfo, plid, ttl, dns_name, ipv6):
        super().__init__(authinfo, "domain.dnsrecords.edit", "AAAA", plid, ttl)

        self["dns_name"] = dns_name
        self["ipv6"] = ipv6


class EditAAAARecordAtexRequest(AAAARecordAtexRequest):
    def __init__(self, authinfo, plid, ttl, dns_name, ipv6, elid):
        super().__init__(authinfo, plid, ttl, dns_name, ipv6)

        self["elid"] = elid


class MXRecordAtexRequest(RecordAtexRequest):
    def __init__(self, authinfo, plid, ttl, dns_name, mx, priority):
        super().__init__(authinfo, "domain.dnsrecords.edit", "MX", plid, ttl)

        self["dns_name"] = dns_name
        self["mx"] = mx
        self["priority"] = priority


class EditMXRecordAtexRequest(MXRecordAtexRequest):
    def __init__(self, authinfo, plid, ttl, dns_name, mx, priority, elid):
        super().__init__(authinfo, plid, ttl, dns_name, mx, priority)

        self["elid"] = elid


class SRVRecordAtexRequest(RecordAtexRequest):
    def __init__(self, authinfo, plid, ttl, address, port, priority, host, srv_priority, weight):
        super().__init__(authinfo, "domain.dnsrecords.edit", "SRV", plid, ttl)

        self["address"] = address
        self["port"] = port
        self["priority"] = priority
        self["host"] = host
        self["srv_priority"] = srv_priority
        self["weight"] = weight


class EditSRVRecordAtexRequest(SRVRecordAtexRequest):
    def __init__(self, authinfo, plid, ttl, address, port, priority, host, srv_priority, weight, elid):
        super().__init__(authinfo, plid, ttl, address, port, priority, host, srv_priority, weight)

        self["elid"] = elid


class CNAMERecordAtexRequest(RecordAtexRequest):
    def __init__(self, authinfo, plid, ttl, canonical_name, dns_name):
        super().__init__(authinfo, "domain.dnsrecords.edit", "CNAME", plid, ttl)

        self["canonical_name"] = canonical_name
        self["dns_name"] = dns_name


class EditCNAMERecordAtexRequest(CNAMERecordAtexRequest):
    def __init__(self, authinfo, plid, ttl, canonical_name, dns_name, elid):
        super().__init__(authinfo, plid, ttl, canonical_name, dns_name)

        self["elid"] = elid


class TXTRecordAtexRequest(RecordAtexRequest):
    def __init__(self, authinfo, plid, ttl, dns_name, txt):
        super().__init__(authinfo, "domain.dnsrecords.edit", "TXT", plid, ttl)

        self["dns_name"] = dns_name
        self["txt"] = txt


class EditTXTRecordAtexRequest(TXTRecordAtexRequest):
    def __init__(self, authinfo, plid, ttl, dns_name, txt, elid):
        super().__init__(authinfo, plid, ttl, dns_name, txt)

        self["elid"] = elid


class NSRecordAtexRequest(RecordAtexRequest):
    def __init__(self, authinfo, plid, ttl, ns_field, ns_name):
        super().__init__(authinfo, "domain.dnsrecords.edit", "NS", plid, ttl)

        self["ns_field"] = ns_field
        self["ns_name"] = ns_name


class EditNSRecordAtexRequest(NSRecordAtexRequest):
    def __init__(self, authinfo, plid, ttl, ns_field, ns_name, elid):
        super().__init__(authinfo, plid, ttl, ns_field, ns_name)

        self["elid"] = elid


class GetAtexRequest(AtexRequest):
    def __init__(self, authinfo, elid):
        super().__init__(authinfo, "domain.dnsrecords")

        self["elid"] = elid


class DeleteAtexRequest(AtexRequest):
    def __init__(self, authinfo, elid, plid):
        super().__init__(authinfo, "domain.dnsrecords.delete")

        self["clicked_button"] = "ok"
        self["elid"] = elid
        self["plid"] = plid
        self["sok"] = "ok"


class AutoAtexRequest(AtexRequest):
    def __init__(self, authinfo, elid):
        super().__init__(authinfo, "domain.dnsrecords.autoconfigns")

        self["clicked_button"] = "ok"
        self["elid"] = elid
        self["sok"] = "ok"


class DnssecAtexRequest(AtexRequest):
    def __init__(self, authinfo, elid):
        super().__init__(authinfo, "domain.dnsrecords.dnssec")

        self["elid"] = elid


class DnssecEnableAtexRequest(AtexRequest):
    def __init__(self, authinfo, dns_to_add, ds_to_add, plid):
        super().__init__(authinfo, "domain.dnsrecords.dnssec")

        self["clicked_button"] = "ok"
        self["dns_to_add"] = dns_to_add
        self["ds_to_add"] = ds_to_add
        self["plid"] = plid
        self["sok"] = "ok"


class SOARecordAtexRequest(RecordAtexRequest):
    def __init__(self, authinfo, ttl, dns_name, elid, email, expire, minimum, refresh, retry):
        super().__init__(authinfo, "domain.dnsrecords.editsoa", "SOA", "", ttl)

        self["dns_name"] = dns_name
        self["elid"] = elid
        self["email"] = email
        self["expire"] = expire
        self["minimum"] = minimum
        self["refresh"] = refresh
        self["retry"] = retry


def domain_list(login: str,
                password: str) -> list[Any]:
    response = ListAtexRequest(f"{login}:{password}").send()
    root = ElementTree.fromstring(response)
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
    response = ListAtexRequest(f"{login}:{password}").raw()
    return response


def domain_add_record_a(domain_id: int,
                        dns_name: str,
                        ip_address: str,
                        ttl: int,
                        login: str,
                        password: str) -> str:
    response = ARecordAtexRequest(authinfo=f"{login}:{password}",
                                  plid=domain_id,
                                  ttl=ttl,
                                  dns_name=dns_name,
                                  ipv4=ip_address).send()
    return pretty_xml_as_string(response)


def domain_add_record_a_raw(domain_id: int,
                            dns_name: str,
                            ip_address: str,
                            ttl: int,
                            login: str,
                            password: str) -> str:
    response = ARecordAtexRequest(authinfo=f"{login}:{password}",
                                  plid=domain_id,
                                  ttl=ttl,
                                  dns_name=dns_name,
                                  ipv4=ip_address).raw()
    return response


def domain_add_record_aaaa(domain_id: int,
                           dns_name: str,
                           ipv6_address: str,
                           ttl: int,
                           login: str,
                           password: str) -> str:
    response = AAAARecordAtexRequest(authinfo=f"{login}:{password}",
                                     plid=domain_id,
                                     ttl=ttl,
                                     dns_name=dns_name,
                                     ipv6=ipv6_address).send()
    return pretty_xml_as_string(response)


def domain_add_record_aaaa_raw(domain_id: int,
                               dns_name: str,
                               ipv6_address: str,
                               ttl: int,
                               login: str,
                               password: str) -> str:
    response = AAAARecordAtexRequest(authinfo=f"{login}:{password}",
                                     plid=domain_id,
                                     ttl=ttl,
                                     dns_name=dns_name,
                                     ipv6=ipv6_address).raw()
    return response


def domain_add_record_mx(domain_id: int,
                         dns_name: str,
                         mx_server: str,
                         priority: int,
                         ttl: int,
                         login: str,
                         password: str) -> str:
    response = MXRecordAtexRequest(authinfo=f"{login}:{password}",
                                   plid=domain_id,
                                   ttl=ttl,
                                   dns_name=dns_name,
                                   mx=mx_server,
                                   priority=priority).send()
    return pretty_xml_as_string(response)


def domain_add_record_mx_raw(domain_id: int,
                             dns_name: str,
                             mx_server: str,
                             priority: int,
                             ttl: int,
                             login: str,
                             password: str) -> str:
    response = MXRecordAtexRequest(authinfo=f"{login}:{password}",
                                   plid=domain_id,
                                   ttl=ttl,
                                   dns_name=dns_name,
                                   mx=mx_server,
                                   priority=priority).raw()
    return response


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
    response = SRVRecordAtexRequest(authinfo=f"{login}:{password}",
                                    plid=domain_id,
                                    ttl=ttl,
                                    host=host,
                                    address=address,
                                    port=port,
                                    priority=priority,
                                    srv_priority=srv_priority,
                                    weight=weight).send()
    return pretty_xml_as_string(response)


def domain_add_record_srv_add(domain_id: int,
                              priority: int,
                              ttl: int,
                              host: str,
                              srv_priority: int,
                              weight: int,
                              port: int,
                              address: str,
                              login: str,
                              password: str) -> str:
    response = SRVRecordAtexRequest(authinfo=f"{login}:{password}",
                                    plid=domain_id,
                                    ttl=ttl,
                                    host=host,
                                    address=address,
                                    port=port,
                                    priority=priority,
                                    srv_priority=srv_priority,
                                    weight=weight).raw()
    return response


def domain_add_record_cname(domain_id: int,
                            dns_name: str,
                            sub_domain: str,
                            ttl: int,
                            login: str,
                            password: str) -> str:
    response = CNAMERecordAtexRequest(authinfo=f"{login}:{password}",
                                      plid=domain_id,
                                      ttl=ttl,
                                      canonical_name=sub_domain,
                                      dns_name=dns_name).send()
    return pretty_xml_as_string(response)


def domain_add_record_cname_raw(domain_id: int,
                                dns_name: str,
                                sub_domain: str,
                                ttl: int,
                                login: str,
                                password: str) -> str:
    response = CNAMERecordAtexRequest(authinfo=f"{login}:{password}",
                                      plid=domain_id,
                                      ttl=ttl,
                                      canonical_name=sub_domain,
                                      dns_name=dns_name).raw()
    return response


def domain_add_record_txt(domain_id: int,
                          dns_name: str,
                          txt_record: str,
                          ttl: int,
                          login: str,
                          password: str) -> str:
    response = TXTRecordAtexRequest(authinfo=f"{login}:{password}",
                                    plid=domain_id,
                                    ttl=ttl,
                                    dns_name=dns_name,
                                    txt=txt_record).send()
    return pretty_xml_as_string(response)


def domain_add_record_txt_raw(domain_id: int,
                              dns_name: str,
                              txt_record: str,
                              ttl: int,
                              login: str,
                              password: str) -> str:
    response = TXTRecordAtexRequest(authinfo=f"{login}:{password}",
                                    plid=domain_id,
                                    ttl=ttl,
                                    dns_name=dns_name,
                                    txt=txt_record).raw()
    return response


def domain_add_record_ns(domain_id: int,
                         ns_name: str,
                         ns_field: str,
                         ttl: int,
                         login: str,
                         password: str) -> str:
    response = NSRecordAtexRequest(authinfo=f"{login}:{password}",
                                   plid=domain_id,
                                   ttl=ttl,
                                   ns_field=ns_field,
                                   ns_name=ns_name).send()
    return pretty_xml_as_string(response)


def domain_add_record_ns_raw(domain_id: int,
                             ns_name: str,
                             ns_field: str,
                             ttl: int,
                             login: str,
                             password: str) -> str:
    response = NSRecordAtexRequest(authinfo=f"{login}:{password}",
                                   plid=domain_id,
                                   ttl=ttl,
                                   ns_field=ns_field,
                                   ns_name=ns_name).raw()
    return response


def domain_get_records(domain_id: int,
                       login: str,
                       password: str) -> list[Any]:
    response = GetAtexRequest(authinfo=f"{login}:{password}",
                              elid=domain_id).send()
    root = ElementTree.fromstring(response)
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
                           password: str) -> str:
    response = GetAtexRequest(authinfo=f"{login}:{password}",
                              elid=domain_id).raw()
    return response


def domain_edit_record_a(record_id: str,
                         domain_id: int,
                         dns_name: str,
                         ip_address: str,
                         ttl: int,
                         login: str,
                         password: str) -> str:
    response = EditARecordAtexRequest(authinfo=f"{login}:{password}",
                                      plid=domain_id,
                                      ttl=ttl,
                                      dns_name=dns_name,
                                      ipv4=ip_address,
                                      elid=record_id).send()
    return pretty_xml_as_string(response)


def domain_edit_record_a_raw(record_id: str,
                             domain_id: int,
                             dns_name: str,
                             ip_address: str,
                             ttl: int,
                             login: str,
                             password: str) -> str:
    response = EditARecordAtexRequest(authinfo=f"{login}:{password}",
                                      plid=domain_id,
                                      ttl=ttl,
                                      dns_name=dns_name,
                                      ipv4=ip_address,
                                      elid=record_id).raw()
    return response


def domain_edit_record_aaaa(record_id: str,
                            domain_id: int,
                            dns_name: str,
                            ipv6_address: str,
                            ttl: int,
                            login: str,
                            password: str) -> str:
    response = EditAAAARecordAtexRequest(authinfo=f"{login}:{password}",
                                         plid=domain_id,
                                         ttl=ttl,
                                         dns_name=dns_name,
                                         ipv6=ipv6_address,
                                         elid=record_id).send()
    return pretty_xml_as_string(response)


def domain_edit_record_aaaa_raw(record_id: str,
                                domain_id: int,
                                dns_name: str,
                                ipv6_address: str,
                                ttl: int,
                                login: str,
                                password: str) -> str:
    response = EditAAAARecordAtexRequest(authinfo=f"{login}:{password}",
                                         plid=domain_id,
                                         ttl=ttl,
                                         dns_name=dns_name,
                                         ipv6=ipv6_address,
                                         elid=record_id).raw()
    return response


def domain_edit_record_mx(record_id: str,
                          domain_id: int,
                          dns_name: str,
                          mx_server: str,
                          priority: int,
                          ttl: int,
                          login: str,
                          password: str) -> str:
    response = EditMXRecordAtexRequest(authinfo=f"{login}:{password}",
                                       plid=domain_id,
                                       ttl=ttl,
                                       dns_name=dns_name,
                                       mx=mx_server,
                                       priority=priority,
                                       elid=record_id).send()
    return pretty_xml_as_string(response)


def domain_edit_record_mx_raw(record_id: str,
                              domain_id: int,
                              dns_name: str,
                              mx_server: str,
                              priority: int,
                              ttl: int,
                              login: str,
                              password: str) -> str:
    response = EditMXRecordAtexRequest(authinfo=f"{login}:{password}",
                                       plid=domain_id,
                                       ttl=ttl,
                                       dns_name=dns_name,
                                       mx=mx_server,
                                       priority=priority,
                                       elid=record_id).raw()
    return response


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
    response = EditSRVRecordAtexRequest(authinfo=f"{login}:{password}",
                                        plid=domain_id,
                                        ttl=ttl,
                                        host=host,
                                        address=address,
                                        port=port,
                                        priority=priority,
                                        srv_priority=srv_priority,
                                        weight=weight,
                                        elid=record_id).send()
    return pretty_xml_as_string(response)


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
    response = EditSRVRecordAtexRequest(authinfo=f"{login}:{password}",
                                        plid=domain_id,
                                        ttl=ttl,
                                        host=host,
                                        address=address,
                                        port=port,
                                        priority=priority,
                                        srv_priority=srv_priority,
                                        weight=weight,
                                        elid=record_id).raw()
    return response


def domain_edit_record_cname(record_id: str,
                             domain_id: int,
                             dns_name: str,
                             sub_domain: str,
                             ttl: int,
                             login: str,
                             password: str) -> str:
    response = EditCNAMERecordAtexRequest(authinfo=f"{login}:{password}",
                                          plid=domain_id,
                                          ttl=ttl,
                                          canonical_name=sub_domain,
                                          dns_name=dns_name, elid=record_id).send()
    return pretty_xml_as_string(response)


def domain_edit_record_cname_raw(record_id: str,
                                 domain_id: int,
                                 dns_name: str,
                                 sub_domain: str,
                                 ttl: int,
                                 login: str,
                                 password: str) -> str:
    response = EditCNAMERecordAtexRequest(authinfo=f"{login}:{password}",
                                          plid=domain_id,
                                          ttl=ttl,
                                          canonical_name=sub_domain,
                                          dns_name=dns_name, elid=record_id).raw()
    return response


def domain_edit_record_txt(record_id: str,
                           domain_id: int,
                           dns_name: str,
                           txt_record: str,
                           ttl: int,
                           login: str,
                           password: str) -> str:
    response = EditTXTRecordAtexRequest(authinfo=f"{login}:{password}",
                                        plid=domain_id,
                                        ttl=ttl,
                                        dns_name=dns_name,
                                        txt=txt_record,
                                        elid=record_id).send()
    return pretty_xml_as_string(response)


def domain_edit_record_txt_raw(record_id: str,
                               domain_id: int,
                               dns_name: str,
                               txt_record: str,
                               ttl: int,
                               login: str,
                               password: str) -> str:
    response = EditTXTRecordAtexRequest(authinfo=f"{login}:{password}",
                                        plid=domain_id,
                                        ttl=ttl,
                                        dns_name=dns_name,
                                        txt=txt_record,
                                        elid=record_id).raw()
    return response


def domain_edit_record_ns(record_id: str,
                          domain_id: int,
                          ns_name: str,
                          ns_field: str,
                          ttl: int,
                          login: str,
                          password: str) -> str:
    response = EditNSRecordAtexRequest(authinfo=f"{login}:{password}",
                                       plid=domain_id,
                                       ttl=ttl,
                                       ns_field=ns_field,
                                       ns_name=ns_name,
                                       elid=record_id).send()
    return pretty_xml_as_string(response)


def domain_edit_record_ns_raw(record_id: str,
                              domain_id: int,
                              ns_name: str,
                              ns_field: str,
                              ttl: int,
                              login: str,
                              password: str) -> str:
    response = EditNSRecordAtexRequest(authinfo=f"{login}:{password}",
                                       plid=domain_id,
                                       ttl=ttl,
                                       ns_field=ns_field,
                                       ns_name=ns_name,
                                       elid=record_id).raw()
    return response


def domain_delete_record(record_id: str,
                         domain_id: int,
                         login: str,
                         password: str) -> str:
    response = DeleteAtexRequest(authinfo=f"{login}:{password}",
                                 elid=record_id,
                                 plid=domain_id).send()
    return pretty_xml_as_string(response)


def domain_delete_record_raw(record_id: str,
                             domain_id: int,
                             login: str,
                             password: str) -> str:
    response = DeleteAtexRequest(authinfo=f"{login}:{password}",
                                 elid=record_id,
                                 plid=domain_id).raw()
    return response


def dns_auto_settings(domain_id: int,
                      login: str,
                      password: str) -> str:
    response = AutoAtexRequest(authinfo=f"{login}:{password}",
                               elid=domain_id).send()
    return pretty_xml_as_string(response)


def dns_auto_settings_raw(domain_id: int,
                          login: str,
                          password: str) -> str:
    response = AutoAtexRequest(authinfo=f"{login}:{password}",
                               elid=domain_id).raw()
    return response


def dnssec_get(domain_id: int,
               login: str,
               password: str) -> str:
    response = DnssecAtexRequest(authinfo=f"{login}:{password}",
                                 elid=domain_id).send()
    return pretty_xml_as_string(response)


def dnssec_get_raw(domain_id: int,
                   login: str,
                   password: str) -> str:
    response = DnssecAtexRequest(authinfo=f"{login}:{password}",
                                 elid=domain_id).raw()
    return response


def dnssec_enable(domain_id: int,
                  dns_to_add: str,
                  ds_to_add: str,
                  login: str,
                  password: str) -> str:
    response = DnssecEnableAtexRequest(authinfo=f"{login}:{password}",
                                       dns_to_add=dns_to_add,
                                       ds_to_add=ds_to_add,
                                       plid=domain_id).send()
    return pretty_xml_as_string(response)


def dnssec_enable_raw(domain_id: int,
                      dns_to_add: str,
                      ds_to_add: str,
                      login: str,
                      password: str) -> str:
    response = DnssecEnableAtexRequest(authinfo=f"{login}:{password}",
                                       dns_to_add=dns_to_add,
                                       ds_to_add=ds_to_add,
                                       plid=domain_id).raw()
    return response


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
    response = SOARecordAtexRequest(authinfo=f"{login}:{password}",
                                    ttl=ttl,
                                    dns_name=dns_name,
                                    elid=domain_id,
                                    email=email,
                                    expire=expire,
                                    minimum=minimum,
                                    refresh=refresh,
                                    retry=retry).send()
    return pretty_xml_as_string(response)


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
    response = SOARecordAtexRequest(authinfo=f"{login}:{password}",
                                    ttl=ttl,
                                    dns_name=dns_name,
                                    elid=domain_id,
                                    email=email,
                                    expire=expire,
                                    minimum=minimum,
                                    refresh=refresh,
                                    retry=retry).raw()
    return response


# Make XML string prettier.
# Source: https://stackoverflow.com/a/1206856
def pretty_xml_as_string(xml_string: str) -> str:
    dom = xml.dom.minidom.parseString(xml_string)
    return dom.toprettyxml()
