from modules.jarm.extensions import jarm_registry

# Import your transforms here
from transforms import IPtoJARMHash

if __name__ == "__main__":
    jarm_registry.write_local_mtz(command="./venv/bin/python3")
