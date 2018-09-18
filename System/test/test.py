#!/usr/bin/env python
"""Main module responsible for testing the software."""

import sys
import os
import unittest
import json
import time

sys.path.append(os.path.dirname(os.getcwd()))

from components import reader
from components import writer
from components import topology_parser as top_par

from components.attack_graph_parser import breadth_first_search
from components.attack_graph_parser import generate_attack_graph

def scalability_test_helper(example_folder):
    """Main function that tests the scalability for different examples."""

    number_runs_per_test = 5

    duration_topology = 0
    duration_bdf = 0
    duration_vuls_preprocessing = 0
    duration_total_time = 0

    for i in range(1, number_runs_per_test+1):

        print("\n\nIteration: "+str(i))
        total_time_start = time.time()

        # Preparing the data for testing
        parent_path = os.path.dirname(os.getcwd())

        # Opening the configuration file.
        config = reader.read_config_file(old_root_path=parent_path)
        topology, duration_topology_new = top_par.parse_topology(example_folder,
                                                                 os.getcwd())

        duration_topology += duration_topology_new

        vuls_orig = reader.read_vulnerabilities(example_folder,
                                                ["example_samba",
                                                 "example_phpmailer"])

        vulnerabilities = {}
        for container_orig in vuls_orig.keys():
            for container_topology in topology.keys():
                if container_orig in container_topology:
                    vulnerabilities[container_topology] = vuls_orig[container_orig]

        att_vec_path = os.path.join(parent_path, config["attack-vector-folder-path"])

        # Returns a tuple of the form:
        # (attack_graph_nodes, attack_graph_edges, duration_bdf, duration_vul_preprocessing)
        attack_graph_tuple = generate_attack_graph(att_vec_path,
                                                   config["preconditions-rules"],
                                                   config["postconditions-rules"],
                                                   topology,
                                                   vulnerabilities,
                                                   example_folder)

        # Unpacking the variables
        duration_bdf += attack_graph_tuple[2]
        duration_vuls_preprocessing += attack_graph_tuple[3]

        no_topology_nodes = len(topology.keys())
        no_topology_edges = 0
        for container in topology.keys():
            no_topology_edges += len(topology[container])

        # We divide them by two because each edge is counted twice.
        no_topology_edges = int(no_topology_edges / 2)
        no_attack_graph_nodes = len(attack_graph_tuple[0])
        no_attack_graph_edges = len(attack_graph_tuple[1])

        duration_total_time += (time.time() - total_time_start)

    # Calculate the averages of the times
    duration_topology = duration_topology/5
    duration_vuls_preprocessing = duration_vuls_preprocessing/5
    duration_bdf = duration_bdf/5
    duration_total_time = duration_topology + duration_vuls_preprocessing + duration_bdf

    # Printing time summary of the attack graph generation.
    writer.print_summary(config["mode"],
                         config["generate_graphs"],
                         no_topology_nodes=no_topology_nodes,
                         no_topology_edges=no_topology_edges,
                         no_attack_graph_nodes=no_attack_graph_nodes,
                         no_attack_graph_edges=no_attack_graph_edges,
                         duration_topology=duration_topology,
                         duration_vuls_preprocessing=duration_vuls_preprocessing,
                         duration_bdf=duration_bdf,
                         duration_total_time=duration_total_time)

    print("Total time elapsed: "+str(duration_total_time)+"\n\n\n")

class MyTest(unittest.TestCase):
    """This class contains the unit tests."""

    def test_bfs_priviledged_exists(self):
        """Testing the creation of attack graph with a priviledged container.
        Here the priviledged container is container2. Container3 is isolated and it can
        only be reached through the docker host."""

        print("Test: Testing an image with a 'priviledged' flag...")

        topology = {"outside" : ["container1"],
                    "container1": ["container2", "outside", "docker host"],
                    "container2": ["container1", "docker host"],
                    "container3": ["docker host"],
                    "docker host": ["container1", "container2", "container3"]}

        exploitable_vuls = {"container1": {"precond" : {"CVE-2015-0000" : 0},
                                           "postcond" : {"CVE-2015-0000" : 3}},
                            "container2" : {"precond" : {"CVE-2015-0001" : 3},
                                            "postcond" : {"CVE-2015-0001" : 4}},
                            "container3": {"precond" : {"CVE-2015-0002" : 3},
                                           "postcond" : {"CVE-2015-0002" : 4}}}

        privileged_access = {"container1" : False, "container2" : True, "container3" : False}

        nodes, edges, _ = breadth_first_search(topology,
                                               exploitable_vuls,
                                               privileged_access)

        # Checking that container3 has been attacked and the edges that lead to it.
        self.assertTrue('container2(ADMIN)|docker host(ADMIN)' in edges)
        self.assertTrue('docker host(ADMIN)|container3(ADMIN)' in edges)
        self.assertTrue('container3(ADMIN)' in nodes)

    def test_bfs_priviledged_dont_exist(self):
        """Testing the creation of attack graph without a priviledged container.
        There is no privileged container. Container3 is isolated and it can
        only be reached through the docker host."""

        print("Test: Testing an image without a 'privileged' flag...")

        topology = {"outside" : ["container1"],
                    "container1": ["container2", "outside", "docker host"],
                    "container2": ["container1", "docker host"],
                    "container3": ["docker host"],
                    "docker host": ["container1", "container2", "container3"]}

        exploitable_vuls = {"container1": {"precond" : {"CVE-2015-0000" : 0},
                                           "postcond" : {"CVE-2015-0000" : 3}},
                            "container2" : {"precond" : {"CVE-2015-0001" : 3},
                                            "postcond" : {"CVE-2015-0001" : 4}},
                            "container3": {"precond" : {"CVE-2015-0002" : 3},
                                           "postcond" : {"CVE-2015-0002" : 4}}}

        privileged_access = {"container1" : False, "container2" : False, "container3" : False}

        nodes, _, _ = breadth_first_search(topology,
                                           exploitable_vuls,
                                           privileged_access)

        # Checking that container3 has not been attacked
        self.assertFalse('container3(NONE)' in nodes)
        self.assertFalse('container3(VOS USER)' in nodes)
        self.assertFalse('container3(VOS ADMIN)' in nodes)
        self.assertFalse('container3(USER)' in nodes)
        self.assertFalse('container3(ADMIN)' in nodes)

        self.assertFalse('docker host(ADMIN)' in nodes)

    def test_empty_graph(self):
        """Testing an empty graph. Empty graph by our definition has
        no nodes."""

        print("Test: Testing an empty attack graph(attacker has no access)...")

        topology = {"outside" : [],
                    "container1": ["container2", "docker host"],
                    "container2": ["container1", "docker host"],
                    "container3": ["docker host"],
                    "docker host": ["container1", "container2", "container3"]}

        exploitable_vuls = {"container1": {"precond" : {"CVE-2015-0000" : 0},
                                           "postcond" : {"CVE-2015-0000" : 3}},
                            "container2" : {"precond" : {"CVE-2015-0001" : 3},
                                            "postcond" : {"CVE-2015-0001" : 4}},
                            "container3": {"precond" : {"CVE-2015-0002" : 3},
                                           "postcond" : {"CVE-2015-0002" : 4}}}

        privileged_access = {"container1" : False, "container2" : False, "container3" : False}

        nodes, edges, _ = breadth_first_search(topology,
                                               exploitable_vuls,
                                               privileged_access)

        # Checking that outside(ADMIN) is the only node.
        self.assertTrue('outside(ADMIN)' not in nodes)

        # The attack graph should have 0 nodes.
        self.assertEqual(len(nodes), 0)

        # The attack graph should have 0 edges.
        self.assertEqual(len(edges), 0)

    def test_clique_attacker(self):
        """Tests an attack graph that has an attacker in a clique
        i.e. connected to every container."""

        print("Test: Testing an all-connected attacker...")

        topology = {"outside" : ["container1", "container2", "container3"],
                    "container1": ["outside", "container2", "docker host"],
                    "container2": ["outside", "container1", "docker host"],
                    "container3": ["outside", "docker host"],
                    "docker host": ["container1", "container2", "container3"]}

        exploitable_vuls = {"container1": {"precond" : {"CVE-2015-0000" : 0},
                                           "postcond" : {"CVE-2015-0000" : 3}},
                            "container2" : {"precond" : {"CVE-2015-0001" : 3},
                                            "postcond" : {"CVE-2015-0001" : 4}},
                            "container3": {"precond" : {"CVE-2015-0002" : 3},
                                           "postcond" : {"CVE-2015-0002" : 4}}}

        privileged_access = {"container1" : False, "container2" : False, "container3" : False}

        nodes, edges, _ = breadth_first_search(topology,
                                               exploitable_vuls,
                                               privileged_access)

        # Checking the nodes
        self.assertEqual(len(nodes), 4)
        self.assertTrue('outside(ADMIN)' in nodes)
        self.assertTrue('container1(USER)' in nodes)
        self.assertTrue('container2(ADMIN)' in nodes)
        self.assertTrue('container3(ADMIN)' in nodes)

        # Checking the edges
        self.assertEqual(len(edges), 3)
        self.assertTrue('outside(ADMIN)|container1(USER)' in edges)
        self.assertTrue('outside(ADMIN)|container2(ADMIN)' in edges)
        self.assertTrue('outside(ADMIN)|container3(ADMIN)' in edges)

    def test_more_than_one_vuls(self):
        """Tests an attack graph that has has more than two ways to attack
        same node from the same node. In this example container2 has two vulnerabilities
        that can potentially be exploited"""

        print("Test: Testing more than one vuls attack from the same node...")

        topology = {"outside" : ["container1"],
                    "container1": ["outside", "container2", "docker host"],
                    "container2": ["outside", "container1", "docker host"],
                    "docker host": ["container1", "container2"]}

        exploitable_vuls = {"container1": {"precond" : {"CVE-2015-0000" : 0},
                                           "postcond" : {"CVE-2015-0000" : 3}},
                            "container2" : {"precond" : {"CVE-2015-0001" : 3,
                                                         "CVE-2016-0001" : 3},
                                            "postcond" : {"CVE-2015-0001" : 4,
                                                          "CVE-2016-0001" : 4}}}

        privileged_access = {"container1" : False, "container2" : False}

        nodes, edges, _ = breadth_first_search(topology,
                                               exploitable_vuls,
                                               privileged_access)

        # Checking the nodes
        self.assertEqual(len(nodes), 3)
        self.assertTrue('outside(ADMIN)' in nodes)
        self.assertTrue('container1(USER)' in nodes)
        self.assertTrue('container2(ADMIN)' in nodes)

        # Checking the edges
        self.assertEqual(len(edges), 2)
        self.assertTrue('outside(ADMIN)|container1(USER)' in edges)
        self.assertTrue('container1(USER)|container2(ADMIN)' in edges)

        # Checking the edge from container1 to container2
        edge = edges['container1(USER)|container2(ADMIN)']
        self.assertEqual('CVE-2015-0001', edge[0])
        self.assertEqual('CVE-2016-0001', edge[1])

    def test_long_attack_graph(self):
        """Tests an attack graph that has 4 nodes and it is in a
        long chain manner with escalating privileges.
        The attacker has to optain outside->container1->container2->container3->container4"""

        print("Test: Testing a long attack graph...")

        topology = {"outside" : ["container1"],
                    "container1": ["outside", "container2", "docker host"],
                    "container2": ["container1", "container3", "docker host"],
                    "container3": ["container2", "container4", "docker host"],
                    "container4": ["container3", "docker host"],
                    "docker host": ["container1", "container2", "container3", "container4"]}

        exploitable_vuls = {"container1": {"precond" : {"CVE-2015-0000" : 0},
                                           "postcond" : {"CVE-2015-0000" : 1}},
                            "container2" : {"precond" : {"CVE-2015-0001" : 1},
                                            "postcond" : {"CVE-2015-0001" : 2}},
                            "container3" : {"precond" : {"CVE-2015-0002" : 2},
                                            "postcond" : {"CVE-2015-0002" : 3}},
                            "container4" : {"precond" : {"CVE-2015-0003" : 3},
                                            "postcond" : {"CVE-2015-0003" : 4}}}

        privileged_access = {"container1" : False,
                             "container2" : False,
                             "container3" : False,
                             "container4" : False}

        nodes, edges, _ = breadth_first_search(topology,
                                               exploitable_vuls,
                                               privileged_access)

        # Checking the nodes
        self.assertEqual(len(nodes), 5)
        self.assertTrue('outside(ADMIN)' in nodes)
        self.assertTrue('container1(VOS USER)' in nodes)
        self.assertTrue('container2(VOS ADMIN)' in nodes)
        self.assertTrue('container3(USER)' in nodes)
        self.assertTrue('container4(ADMIN)' in nodes)

        # Checking the edges
        self.assertEqual(len(edges), 4)
        self.assertTrue('outside(ADMIN)|container1(VOS USER)' in edges)
        self.assertTrue('container1(VOS USER)|container2(VOS ADMIN)' in edges)
        self.assertTrue('container2(VOS ADMIN)|container3(USER)' in edges)
        self.assertTrue('container3(USER)|container4(ADMIN)' in edges)

    def test_big_real_example(self):
        """Testing the example from atsea shop app. It has 4 containers in total. However
        only two of them have vulnerabilities."""

        print("Test: Testing a real example...")

        # Preparing the data for testing
        example_folder = os.path.join(os.getcwd(), "atsea")
        parent_path = os.path.dirname(os.getcwd())

        # Opening the configuration file.
        config = reader.read_config_file(old_root_path=parent_path)

        topology_path = os.path.join(os.getcwd(), "atsea", "topology.json")
        with open(topology_path) as topology_file:
            topology = json.load(topology_file)

        vulnerabilities = reader.read_vulnerabilities(example_folder, topology.keys())

        # Running the attack graph generator
        att_vec_path = os.path.join(parent_path, config["attack-vector-folder-path"])
        nodes, edges, _, _ = generate_attack_graph(att_vec_path,
                                                   config["preconditions-rules"],
                                                   config["postconditions-rules"],
                                                   topology,
                                                   vulnerabilities,
                                                   example_folder)

        # Checking the nodes
        self.assertEqual(len(nodes), 5)
        self.assertTrue('outside(ADMIN)' in nodes)
        self.assertTrue('atsea_app(ADMIN)' in nodes)
        self.assertTrue('atsea_app(USER)' in nodes)
        self.assertTrue('atsea_db(ADMIN)' in nodes)
        self.assertTrue('atsea_db(USER)' in nodes)

        # Checking the edges
        self.assertEqual(len(edges), 4)
        self.assertTrue('outside(ADMIN)|atsea_app(ADMIN)' in edges)
        self.assertTrue('outside(ADMIN)|atsea_app(USER)' in edges)
        self.assertTrue('outside(ADMIN)|atsea_db(ADMIN)' in edges)
        self.assertTrue('outside(ADMIN)|atsea_db(USER)' in edges)

    def test_scalability_1(self):
        """Doing scalability testing of samba and phpmailer example. It has
        1 phpmailer container and 1 samba container."""

        print("Test: Scalability test of samba and phpmailer example...")

        # Preparing the data for testing
        example_folder = os.path.join(os.getcwd(), "1_example")
        #scalability_test_helper(example_folder)

    def test_scalability_5(self):
        """Doing scalability testing of samba and phpmailer example. It has
        1 phpmailer container and 5 samba containers."""

        print("Test: Scalability test of 5 samba and phpmailer example...")

        # Preparing the data for testing
        example_folder = os.path.join(os.getcwd(), "5_example")
        #scalability_test_helper(example_folder)


    def test_scalability_20(self):
        """Doing scalability testing of samba and phpmailer example. It has
        1 phpmailer container and 20 samba containers."""

        print("Test: Scalability test of 20 samba and phpmailer example...")

        # Preparing the data for testing
        example_folder = os.path.join(os.getcwd(), "20_example")
        #scalability_test_helper(example_folder)

    def test_scalability_50(self):
        """Doing scalability testing of samba and phpmailer example. It has
        1 phpmailer container and 50 samba containers."""

        print("Test: Scalability test of 50 samba and phpmailer example...")

        # Preparing the data for testing
        example_folder = os.path.join(os.getcwd(), "50_example")
        #scalability_test_helper(example_folder)

    def test_scalability_100(self):
        """Doing scalability testing of samba and phpmailer example. It has
        1 phpmailer container and 100 samba containers."""

        print("Test: Scalability test of 100 samba and phpmailer example...")

        # Preparing the data for testing
        example_folder = os.path.join(os.getcwd(), "100_example")
        #scalability_test_helper(example_folder)

    def test_scalability_500(self):
        """Doing scalability testing of samba and phpmailer example. It has
        1 phpmailer container and 500 samba containers."""

        print("Test: Scalability test of 500 samba and phpmailer example...")

        # Preparing the data for testing
        example_folder = os.path.join(os.getcwd(), "500_example")
        #scalability_test_helper(example_folder)

    def test_scalability_1000(self):
        """Doing scalability testing of samba and phpmailer example. It has
        1 phpmailer container and 1000 samba containers."""

        print("Test: Scalability test of 1000 samba and phpmailer example...")

        # Preparing the data for testing
        example_folder = os.path.join(os.getcwd(), "1000_example")
        scalability_test_helper(example_folder)

if __name__ == "__main__":
    print("Testing the attack graph generator...")

    unittest.main()
