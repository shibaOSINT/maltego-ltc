from maltego_trx.entities import IPAddress, Hash
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform, UIM_FATAL
from maltego_trx.transform import DiscoverableTransform

from modules.jarm.extensions import jarm_registry, jarm_set

from jarm.scanner.scanner import Scanner


@jarm_registry.register_transform(display_name="Extract TLS extensions hash", input_entity=Hash,
                                  description='Extract the last 32 characters of the JARM hash, related to the '
                                              'extensions used by the TLS server. '
                                              'According to the '
                                              'authors of this library: "The remaining 32 characters are a truncated '
                                              'SHA256 hash of the cumulative extensions sent by the server, '
                                              'ignoring x509 certificate data".',
                                  output_entities=[Hash],
                                  transform_set=jarm_set)
class ExtractTLSextensionsHash(DiscoverableTransform):

    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform):

        if request.getProperty("type") == "JARM":
            tls_extension = request.getProperty("tls_extension")
        else:
            response.addUIMessage("Not a JARM hash!", messageType=UIM_FATAL)
            return
        ent = response.addEntity(type=Hash, value=tls_extension)
        ent.addProperty(fieldName="type", displayName="Hash Type",
                        matchingRule="strict", value="TLS extensions from JARM")
