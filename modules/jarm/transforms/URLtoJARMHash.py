from maltego_trx.entities import Domain, Hash, URL
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform
from maltego_trx.transform import DiscoverableTransform

from modules.jarm.extensions import jarm_registry, jarm_set
from modules.jarm.transforms.IPtoJARMHash import IPtoJARMHash

from jarm.scanner.scanner import Scanner
from urllib.parse import urlparse


@jarm_registry.register_transform(display_name="To JARM hash", input_entity=URL,
                                  description='Returns the JARM hash of the TLS configuration running on the port '
                                              'specified in the URL, if not specified, it will default to 443. '
                                              'Example of the format expected: https://google.com:443 or https://192.168.1.1:443',
                                  output_entities=[Hash],
                                  transform_set=jarm_set)
class URLtoJARMHash(IPtoJARMHash):

    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform):
        host_url = request.getProperty("theurl")
        host_url = urlparse(host_url)
        results = cls.scan_ip_or_domain(host_url.hostname, host_url.port)
        cls.create_jarm_hash(response=response, results=results)
