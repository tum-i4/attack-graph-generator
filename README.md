# Docker Attack Graph Generator


## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.


### Prerequisites

It works currently only on Ubuntu 16.04.4 LTS.
It is tested on a virtual machine containing the above-mentioned operating system from scratch.

Executing the program for the first time will download all of the needed libraries/components including:

-python3.6
-pip3
-docker-ce
-docker-compose
-go (also setting the path)
-clairctl
-graphviz
-yaml
-networkx
-numpy


### Installing and Running

In order to run the program, the following script should be run:

```
$ sudo ./attack-graph-generator.sh ./examples/atsea

```

* The command starts the attack-graph-generator.sh script, generates an attack graph based on the system ./examples/atsea.

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



