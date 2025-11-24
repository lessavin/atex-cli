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


class Atex:
    """
    Atex class.
    Use this to make all requests to Atex API.
    Otherwise, you can use other request classes to make your own.
    """

    def __init__(self, authinfo):
        self.authinfo = authinfo

    def list(self) -> list[Any]:
        response = ListAtexRequest(self.authinfo).send()
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

    def add_a(self,
              domain_id: int,
              dns_name: str,
              ip_address: str,
              ttl: int) -> str:
        response = ARecordAtexRequest(authinfo=self.authinfo,
                                      plid=domain_id,
                                      ttl=ttl,
                                      dns_name=dns_name,
                                      ipv4=ip_address).send()
        return pretty_xml_as_string(response)

    def add_aaaa(self,
                 domain_id: int,
                 dns_name: str,
                 ipv6_address: str,
                 ttl: int) -> str:
        response = AAAARecordAtexRequest(authinfo=self.authinfo,
                                         plid=domain_id,
                                         ttl=ttl,
                                         dns_name=dns_name,
                                         ipv6=ipv6_address).send()
        return pretty_xml_as_string(response)

    def add_mx(self,
               domain_id: int,
               dns_name: str,
               mx_server: str,
               priority: int,
               ttl: int) -> str:
        response = MXRecordAtexRequest(authinfo=self.authinfo,
                                       plid=domain_id,
                                       ttl=ttl,
                                       dns_name=dns_name,
                                       mx=mx_server,
                                       priority=priority).send()
        return pretty_xml_as_string(response)

    def add_srv(self,
                domain_id: int,
                priority: int,
                ttl: int,
                host: str,
                srv_priority: int,
                weight: int,
                port: int,
                address: str) -> str:
        response = SRVRecordAtexRequest(authinfo=self.authinfo,
                                        plid=domain_id,
                                        ttl=ttl,
                                        host=host,
                                        address=address,
                                        port=port,
                                        priority=priority,
                                        srv_priority=srv_priority,
                                        weight=weight).send()
        return pretty_xml_as_string(response)

    def add_cname(self,
                  domain_id: int,
                  dns_name: str,
                  sub_domain: str,
                  ttl: int) -> str:
        response = CNAMERecordAtexRequest(authinfo=self.authinfo,
                                          plid=domain_id,
                                          ttl=ttl,
                                          canonical_name=sub_domain,
                                          dns_name=dns_name).send()
        return pretty_xml_as_string(response)

    def add_txt(self,
                domain_id: int,
                dns_name: str,
                txt_record: str,
                ttl: int) -> str:
        response = TXTRecordAtexRequest(authinfo=self.authinfo,
                                        plid=domain_id,
                                        ttl=ttl,
                                        dns_name=dns_name,
                                        txt=txt_record).send()
        return pretty_xml_as_string(response)

    def add_ns(self,
               domain_id: int,
               ns_name: str,
               ns_field: str,
               ttl: int) -> str:
        response = NSRecordAtexRequest(authinfo=self.authinfo,
                                       plid=domain_id,
                                       ttl=ttl,
                                       ns_field=ns_field,
                                       ns_name=ns_name).send()
        return pretty_xml_as_string(response)

    def get(self,
            domain_id: int):
        response = GetAtexRequest(authinfo=self.authinfo,
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

    def edit_a(self,
               record_id: str,
               domain_id: int,
               dns_name: str,
               ip_address: str,
               ttl: int) -> str:
        response = EditARecordAtexRequest(authinfo=self.authinfo,
                                          plid=domain_id,
                                          ttl=ttl,
                                          dns_name=dns_name,
                                          ipv4=ip_address,
                                          elid=record_id).send()
        return pretty_xml_as_string(response)

    def edit_aaaa(self,
                  record_id: str,
                  domain_id: int,
                  dns_name: str,
                  ipv6_address: str,
                  ttl: int) -> str:
        response = EditAAAARecordAtexRequest(authinfo=self.authinfo,
                                             plid=domain_id,
                                             ttl=ttl,
                                             dns_name=dns_name,
                                             ipv6=ipv6_address,
                                             elid=record_id).send()
        return pretty_xml_as_string(response)

    def edit_mx(self,
                record_id: str,
                domain_id: int,
                dns_name: str,
                mx_server: str,
                priority: int,
                ttl: int) -> str:
        response = EditMXRecordAtexRequest(authinfo=self.authinfo,
                                           plid=domain_id,
                                           ttl=ttl,
                                           dns_name=dns_name,
                                           mx=mx_server,
                                           priority=priority,
                                           elid=record_id).send()
        return pretty_xml_as_string(response)

    def edit_srv(self,
                 record_id: str,
                 domain_id: int,
                 priority: int,
                 ttl: int,
                 host: str,
                 srv_priority: int,
                 weight: int,
                 port: int,
                 address: str) -> str:
        response = EditSRVRecordAtexRequest(authinfo=self.authinfo,
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

    def edit_cname(self,
                   record_id: str,
                   domain_id: int,
                   dns_name: str,
                   sub_domain: str,
                   ttl: int) -> str:
        response = EditCNAMERecordAtexRequest(authinfo=self.authinfo,
                                              plid=domain_id,
                                              ttl=ttl,
                                              canonical_name=sub_domain,
                                              dns_name=dns_name, elid=record_id).send()
        return pretty_xml_as_string(response)

    def edit_txt(self,
                 record_id: str,
                 domain_id: int,
                 dns_name: str,
                 txt_record: str,
                 ttl: int) -> str:
        response = EditTXTRecordAtexRequest(authinfo=self.authinfo,
                                            plid=domain_id,
                                            ttl=ttl,
                                            dns_name=dns_name,
                                            txt=txt_record,
                                            elid=record_id).send()
        return pretty_xml_as_string(response)

    def edit_ns(self,
                record_id: str,
                domain_id: int,
                ns_name: str,
                ns_field: str,
                ttl: int) -> str:
        response = EditNSRecordAtexRequest(authinfo=self.authinfo,
                                           plid=domain_id,
                                           ttl=ttl,
                                           ns_field=ns_field,
                                           ns_name=ns_name,
                                           elid=record_id).send()
        return pretty_xml_as_string(response)

    def delete(self,
               record_id: str,
               domain_id: int) -> str:
        response = DeleteAtexRequest(authinfo=self.authinfo,
                                     elid=record_id,
                                     plid=domain_id).send()
        return pretty_xml_as_string(response)

    def auto(self,
             domain_id: int) -> str:
        response = AutoAtexRequest(authinfo=self.authinfo,
                                   elid=domain_id).send()
        return pretty_xml_as_string(response)

    def dnssec(self,
               domain_id: int) -> str:
        response = DnssecAtexRequest(authinfo=self.authinfo,
                                     elid=domain_id).send()
        return pretty_xml_as_string(response)

    def dnssec_enable(self,
                      domain_id: int,
                      dns_to_add: str,
                      ds_to_add: str) -> str:
        response = DnssecEnableAtexRequest(authinfo=self.authinfo,
                                           dns_to_add=dns_to_add,
                                           ds_to_add=ds_to_add,
                                           plid=domain_id).send()
        return pretty_xml_as_string(response)

    def soa(self,
            domain_id: int,
            dns_name: str,
            email: str,
            refresh: bool,
            retry: int,
            expire: int,
            minimum: int,
            ttl: int) -> str:
        response = SOARecordAtexRequest(authinfo=self.authinfo,
                                        ttl=ttl,
                                        dns_name=dns_name,
                                        elid=domain_id,
                                        email=email,
                                        expire=expire,
                                        minimum=minimum,
                                        refresh=refresh,
                                        retry=retry).send()
        return pretty_xml_as_string(response)


# Make XML string prettier.
# Source: https://stackoverflow.com/a/1206856
def pretty_xml_as_string(xml_string: str) -> str:
    dom = xml.dom.minidom.parseString(xml_string)
    return dom.toprettyxml()
