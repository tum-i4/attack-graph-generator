"""Module for generating big docker compose files."""

import os
import yaml

def generate_compose_file(times_samba):
    """Function that generates the docker-compose.yml with number of samba containers."""

    data = {"version" : "2",
            "networks" : {"frontend" : {"driver" : "bridge"},
                          "backend" : {"driver" : "bridge"}},
            "services" : {"phpmailer" : {"build" : "./phpmailer",
                                         "networks" : ["frontend"],
                                         "ports" : [80]}}}

    for i in range(1, times_samba + 1):
        name_container = "samba"+str(i)
        dict_container = {"build" : "./samba",
                          "networks" : ["frontend"],
                          "tty" : True}
        data["services"][name_container] = dict_container


    with open(os.path.join(os.getcwd(), 'docker-compose.yml'), 'w') as outfile:
        yaml.dump(data, outfile, default_flow_style=False)

generate_compose_file(1000)
