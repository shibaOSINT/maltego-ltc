import os

from maltego_trx.entities import Phrase, DNS, IPAddress
from maltego_trx.maltego import MaltegoMsg, MaltegoTransform
from maltego_trx.transform import DiscoverableTransform

from modules.nmap.extensions import nmap_registry, nmap_set
from modules.nmap.utils.commands import COMMANDS
from modules.nmap.utils.nmap_interaction import NmapOrchestrator
from modules.nmap.utils.toentities import dict_to_entities
from modules.nmap.config import TOP_PORT_SCAN_NUMBER

config_file_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.py")


@nmap_registry.register_transform(display_name="To Open Ports (-sV -A)", input_entity="maltego.CIDR",
                                  description=f'Probe open ports to determine service/version info. Command: "-sV -A"',
                                  output_entities=[IPAddress],
                                  transform_set=nmap_set)
class NetblockToOpenPorts(DiscoverableTransform):
    CMD = "{target} -sV -A"
    @classmethod
    def create_entities(cls, request: MaltegoMsg, response: MaltegoTransform):
        netblock_cidr = request.Value
        parsing_function = COMMANDS[cls.CMD]
        cmd = cls.CMD.format(target=netblock_cidr)
        cont = NmapOrchestrator.execute_command(cmd, parsing_function)
        dict_to_entities(cont, response)
