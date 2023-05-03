from maltego_trx.entities import DNS, Hash
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform
from maltego_trx.transform import DiscoverableTransform

from modules.jarm.extensions import jarm_registry, jarm_set
from modules.jarm.transforms.IPtoJARMHash import IPtoJARMHash
from jarm.scanner.scanner import Scanner


@jarm_registry.register_transform(display_name="To JARM hash", input_entity=DNS,
                                  description='Returns the JARM hash of the TLS configuration running on port 443. '
                                              'To scan another port, please use a URL Entity.',
                                  output_entities=[Hash],
                                  transform_set=jarm_set)
class DNSnametoJARMHash(IPtoJARMHash):
    pass
