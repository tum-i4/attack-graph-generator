# Project Title

Attack Graph Generator
 If it is started for the first time and some of the dependencies are installed. Please however not that the list is in progress and it is not complete. Use the steps from above.


## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.


### Prerequisites

It works currently only on Ubuntu 16.04.4 LTS
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
$ ./attack-graph-generator.sh ./examples/atsea database

```

* The command starts the attack-graph-generator.sh script, generates an attack graph based on the system ./examples/atsea with the goal container that we want to achieve named database.

This would download and install the required libraries and set up env variables when run for the furst time. Then it will do the attack graph analysis.
In the config file, there is a possiblity to indicate online/offline mode. This means that offline mode does not use internet connection and we skip the vulnerabilities calculation step with clair. However we assume that the vulnerabilites files are already there and in the right location and they are produced by clair and named as such.

Other examples are
```
$ ./attack-graph-generator.sh ./examples/javaee movieplex7
$ ./attack-graph-generator.sh ./examples/example samba
$ ./attack-graph-generator.sh ./examples/examplebig samba4
$ ./attack-graph-generator.sh ./examples/examplebigbig samba9

```

* Please note that on the first try, clair populates the database, so that is why the attack graph will be empty.
* Also building the images in the vulnerability-parser takes more time, the first time it is built.



