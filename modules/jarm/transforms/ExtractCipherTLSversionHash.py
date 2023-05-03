from maltego_trx.entities import IPAddress, Hash
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform, UIM_FATAL
from maltego_trx.transform import DiscoverableTransform

from modules.jarm.extensions import jarm_registry, jarm_set

from jarm.scanner.scanner import Scanner


@jarm_registry.register_transform(display_name="Extract cipher and TLS version hash", input_entity=Hash,
                                  description='Extract the first 30 characters of the JARM hash, related to the ciphers'
                                              ' picked by the TLS server and the TLS version used. According to the '
                                              'authors of this library: "When comparing JARM fingerprints, if the first'
                                              ' 30 characters are the same but the last 32 are different, this would '
                                              'mean that the servers have very similar configurations, accepting the '
                                              'same versions and ciphers, though not exactly the same given the '
                                              'extensions are different".',
                                  output_entities=[Hash],
                                  transform_set=jarm_set)
class ExtractCipherTLSversionHash(DiscoverableTransform):

    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform):

        if request.getProperty("type") == "JARM":
            cipher_n_tls_hash = request.getProperty("ciphers_and_tls_version")
        else:
            response.addUIMessage("Not a JARM hash!", messageType=UIM_FATAL)
            return
        ent = response.addEntity(type=Hash, value=cipher_n_tls_hash)
        ent.addProperty(fieldName="type", displayName="Hash Type",
                        matchingRule="strict", value="Ciphers and TLS version from JARM")