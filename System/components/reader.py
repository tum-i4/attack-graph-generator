#!/usr/bin/env python
"""Module responsible for all the input reading and validation."""

import os
import json
import yaml
import sys

def validate_command_line_input(arguments):
    """This function validates the command line user input."""
    print("Command-line input validation...\n")

    is_valid = True

    # Check if the user has entered right number of arguments.
    if len(arguments) != 3:
        print("Incorrect number of arguments.")
        is_valid = False

    # Check if the specified folder exists.
    if is_valid:
        if not os.path.exists(arguments[1]):
            print("The entered example folder name does not exist.")
            is_valid = False

    # Check if there is a docker-compose.yml file in the specified folder.
    if is_valid:
        content = os.listdir(arguments[1])
        if "docker-compose.yml" not in content:
            print("docker-compose.yml is missing in the folder "+arguments[1])
            is_valid = False

    # Check if the goal property is in the docker-compose.yml file.
    if is_valid:

        # See if goal state is present in docker-compose.yml.
        compose_file = read_docker_compose_file(arguments[1])

        goal_container_present = False
        if 'services' in compose_file.keys():
            services = compose_file['services']
            if arguments[2] in services.keys():
                goal_container_present = True

        if not goal_container_present:
            print("The goal container is not wrong. Please choose one of the following: "
                  + str(list(services.keys())))
            is_valid = False

    return is_valid

def validate_config_file():
    """This function validates the config file content."""

    print("Config file content validation...\n")

    is_valid = True
    config_file = read_config_file()

    # Check if the main keywords are present in the config file.
    main_keywords = ["attack-vector-filter",
                     "attack-vector-folder-path",
                     "examples-results-path",
                     "mode"]

    for main_keyword in main_keywords:
        if main_keyword not in config_file.keys():
            print("'"+main_keyword+"' keyword is missing in the config file.")
            is_valid = False

    # Check if the filter keywords are present in the config file
    if is_valid:
        filter_keywords = ["accessVector",
                           "accessComplexity",
                           "authentication",
                           "confidentialityImpact",
                           "integrityImpact"]
        for filter_keyword in filter_keywords:
            if filter_keyword not in config_file["attack-vector-filter"].keys():
                print("'"+filter_keyword
                      + "' filter keyword is missing in the config file.")
                is_valid = False

    # Check if the filter keywords have the right values.
    if is_valid:
        filter_vulnerabilities = config_file["attack-vector-filter"]
        for criterium in filter_vulnerabilities.keys():
            if criterium == "accessVector":
                if filter_vulnerabilities[criterium] != "NETWORK" and \
                   filter_vulnerabilities[criterium] != "LOCAL" and \
                   filter_vulnerabilities[criterium] != "ADJACENT_NETWORK":
                    is_valid = False
            elif criterium == "accessComplexity":
                if filter_vulnerabilities[criterium] != "LOW" and \
                   filter_vulnerabilities[criterium] != "MEDIUM" and \
                   filter_vulnerabilities[criterium] != "HIGH":
                    is_valid = False
            elif criterium == "authentication":
                if filter_vulnerabilities[criterium] != "NONE" and \
                   filter_vulnerabilities[criterium] != "SINGLE" and \
                   filter_vulnerabilities[criterium] != "MULTIPLE":
                    is_valid = False
            elif criterium == "confidentialityImpact":
                if filter_vulnerabilities[criterium] != "NONE" and \
                   filter_vulnerabilities[criterium] != "PARTIAL" and \
                   filter_vulnerabilities[criterium] != "COMPLETE":
                    is_valid = False
            elif criterium == "integrityImpact":
                if filter_vulnerabilities[criterium] != "NONE" and \
                   filter_vulnerabilities[criterium] != "PARTIAL" and \
                   filter_vulnerabilities[criterium] != "COMPLETE":
                    is_valid = False

            if not is_valid:
                print("Value: "+filter_vulnerabilities[criterium]
                      + " is invalid for criterum "+criterium)
                break

    # Check if the mode keyword has the right values
    if is_valid:
        config_mode = config_file["mode"]
        if config_mode != "offline" and config_mode != "online":
            is_valid = False
            print("Value: "+config_mode
                      + " is invalid for keyword mode")
            sys.exit(0)
        
        # Checks if clairctl has been installed.
        elif config_mode == "online":
            print("Checking if clairctl has been installed")
            
            home = os.path.expanduser("~")
            os.path.exists(os.path.join(home,
                                        "golang"
                                        "go",
                                        "bin",
                                        "src",
                                        "github.com",
                                        "jgsqware",
                                        "clairctl"))

    

    # Check if the paths for "attack-vector-folder-path" and "examples-results-path" are valid
    if is_valid:
        paths = ["attack-vector-folder-path", "examples-results-path"]
        current_directory = os.getcwd()
        for path in paths:
            combined_path = os.path.join(current_directory, config_file[path])
            if not os.path.exists(combined_path):
                print(combined_path+" does not exist.")
                is_valid = False

    return is_valid

def read_attack_vector_files(attack_vector_folder_path):
    """It reads the attack vector files."""

    attack_vector_list = []

    attack_vector_filenames = os.listdir(attack_vector_folder_path)

    # Iterating through the attack vector files.
    for attack_vector_filename in attack_vector_filenames:

        # Load the attack vector.
        if not attack_vector_filename.startswith("nvdcve"):
            continue
        with open(os.path.join(attack_vector_folder_path, attack_vector_filename)) as att_vec:
            attack_vector_list.append(json.load(att_vec))

    return attack_vector_list

def read_topology(example_folder_path):
    """Reads the topology .json file."""

    config = read_config_file()
    folder_name = os.path.basename(example_folder_path)
    topology_path = os.path.join(config["examples-results-path"],
                                 folder_name,
                                 "topology.json")

    with open(topology_path) as topology_file:
        topology = json.load(topology_file)

    return topology

def read_vulnerabilities(example_folder_path, container_name):
    """This function reads the .json file for the vulnerabilities of a container."""

    config = read_config_file()
    folder_name = os.path.basename(example_folder_path)
    vulnerabilities_path = os.path.join(config["examples-results-path"],
                                        folder_name,
                                        container_name+"-vulnerabilities.json")

    with open(vulnerabilities_path) as vul_file:
        vulnerabilities = json.load(vul_file)

    return vulnerabilities

def read_docker_compose_file(example_folder_path):
    """This function is responsible for reading the docker-compose file of the container."""

    with open(os.path.join(example_folder_path, "docker-compose.yml"), "r") as compose_file:
        docker_compose_file = yaml.load(compose_file)

    return docker_compose_file

def read_config_file(old_root_path=""):
    """This function is responsible for reading the config file."""

    with open(os.path.join(old_root_path, "config.yml"), "r") as stream:
        try:
            config_file = yaml.load(stream)
        except yaml.YAMLError as exc:
            print(exc)

    return config_file

def read_clairctl_config_file(clairctl_home):
    """This function is responsible for reading the clairctl config file."""

    with open(os.path.join(clairctl_home, "clairctl.yml"), "r") as clair_config:
        clair_config = yaml.load(clair_config)
    return clair_config
