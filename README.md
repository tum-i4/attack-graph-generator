# Attack Graph Generation for Microservice Architecture

Microservices are increasingly dominating the field of service sys-
tems, among their many characteristics are technology hetero-
geneity, communicating small services, and automated deployment.
Therefore, with the increase of utilizing third-party components
distributed as images, the potential vulnerabilities existing in a
microservice-based system increase.

One of the most famous microservice architectures is Docker. This project generates attack graphs for Docker projects.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

This project works currently only on Ubuntu 16.04.4 LTS. Executing the program for the first time will download all of the needed libraries/components including:

* [Python 3.6](https://www.python.org/downloads/) - a programming language.
* [Pip](https://pypi.org/project/pip/) - a tool for installing Python packages.
* [Docker Community Edition (CE)](https://docs.docker.com/install/linux/docker-ce/ubuntu/) - a computer program that performs operating-system-level virtualization, also known as "containerization".
* [Docker Compose](https://docs.docker.com/compose/) - a tool for defining and running multi-container Docker applications.
* [Go](https://github.com/golang/go) - an open source programming language that makes it easy to build simple, reliable, and efficient software.
* [Clairctl](https://github.com/jgsqware/clairctl) - a lightweight command-line tool doing the bridge between Registries as Docker Hub, Docker Registry or Quay.io, and the CoreOS vulnerability tracker, Clair.
* [Graphviz](https://www.graphviz.org/) - an open source graph visualization software.
* [Yaml](http://yaml.org/) - a human-readable data serialization language.
* [Networkx](https://networkx.github.io/) - a Python package for the creation, manipulation, and study of the structure, dynamics, and functions of complex networks.
* [Numpy](http://www.numpy.org/) - a fundamental package for scientific computing with Python.

### Installing

All of the libraries/components indicated above are automatically installed during the first run of the program. For how to run the program, please refer to the commands bellow.

### Running

In order to run the program, the user needs to enter the home directory of the project and the following command on the terminal should be run:

```
$ sudo ./attack-graph-generator.sh ./examples/atsea

```

* The command starts the attack-graph-generator.sh script and generates an attack graph based on the system ./examples/atsea.

This command will download and install the required libraries and set up env variables when run for the first time. Then, it performs the attack graph analysis.
In the config file, there is a possiblity to indicate online/offline mode. This means that offline mode does not use internet connection and we skip the vulnerabilities calculation step with clair. However we assume that the vulnerabilites files are already there and in the right location and they are produced by clair and named as such.

Other examples are
```
$ sudo ./attack-graph-generator.sh ./examples/javaee
$ sudo ./attack-graph-generator.sh ./examples/example
$ sudo ./attack-graph-generator.sh ./examples/netflix-oss-example

```

* Please note that on the first try, clair populates the database, so that is why the attack graph will be empty.
* Also building the images in the vulnerability-parser takes more time, the first time it is built.

* It is tested on a virtual machine running on the above-mentioned operating system.

## Authors

Stevica Bozhinoski stevica.bozhinoski@tum.de
Amjad Ibrahim amjad.ibrahim@tum.de

## License

## Acknowledgments

We would like to thank the teams of [Clair](https://github.com/coreos/clair) and [Clairctl](https://github.com/jgsqware/clairctl) for their vulnerabilities generator, which is an integral part of our system.
