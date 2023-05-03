from maltego_trx.entities import IPAddress, Hash
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform
from maltego_trx.transform import DiscoverableTransform

from modules.jarm.extensions import jarm_registry, jarm_set

from jarm.scanner.scanner import Scanner


@jarm_registry.register_transform(display_name="To JARM hash", input_entity=IPAddress,
                                  description='Returns the JARM hash of the TLS configuration running on port 443. '
                                              'To scan another port, please use a URL Entity.',
                                  output_entities=[Hash],
                                  transform_set=jarm_set)
class IPtoJARMHash(DiscoverableTransform):

    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform):
        host = request.Value
        results = cls.scan_ip_or_domain(host)
        cls.create_jarm_hash(response=response, results=results)

    @staticmethod
    def create_jarm_hash(response, results):
        hash_jarm, ciphers_and_tls_version, tls_extension, host, port = results
        ent = response.addEntity(Hash, hash_jarm)
        ent.addProperty(fieldName="ciphers_and_tls_version", displayName="Cipher and TLS version hash",
                        matchingRule="strict", value=ciphers_and_tls_version)
        ent.addProperty(fieldName="tls_extension", displayName="TLS extension hash",
                        matchingRule="strict", value=tls_extension)
        ent.addProperty(fieldName="host", displayName="Host",
                        matchingRule="loose", value=host)
        ent.addProperty(fieldName="port", displayName="Port",
                        matchingRule="loose", value=port)
        ent.addProperty(fieldName="type", displayName="Hash Type",
                        matchingRule="strict", value="JARM")

    @staticmethod
    def scan_ip_or_domain(host, port=443):
        hash_jarm, host, port = Scanner.scan(host, port)
        ciphers_and_tls_version = hash_jarm[:30]
        tls_extension = hash_jarm[30:]
        return [hash_jarm, ciphers_and_tls_version, tls_extension, host, port]
