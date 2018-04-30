#!/bin/bash

echo ""
echo "Checking if dependencies are installed..."
# Checking if python is installed.
path_python=$(which python3)
length_path_python=$(expr length "$path_python")
if [ "$length_path_python3" = "0" ]; then
     echo "Python3.6 is not installed."
     sudo apt-get update
     sudo apt-get install python3.6
else
     echo "Python3.6 is installed."
fi

path_pip3=$(which pip3)
length_path_pip3=$(expr length "$path_pip3")
if [ "$length_path_pip3" = "0" ]; then
     echo "Pip3 is not installed."
     sudo apt-get install python3-pip
else
     echo "Pip3 is installed."
fi

# Checking if docker is installed.
path_docker=$(which docker)
length_path_docker=$(expr length "$path_docker")
if [ "$length_path_docker" = "0" ]; then
     echo "Docker is not installed."
     sudo apt-get install apt-transport-https ca-certificates curl software-properties-common
     curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
     sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu xenial stable"
     sudo apt-get update
     apt-cache search docker-ce
     sudo apt-get install docker-ce
else
     echo "Docker is installed."
fi

# Checking if docker-compose is installed.
path_docker_compose=$(which docker-compose)
length_path_docker_compose=$(expr length "$path_docker_compose")
if [ "$length_path_docker_compose" = "0" ]; then
     echo "Docker-compose is not installed."
     sudo curl -L https://github.com/docker/compose/releases/download/1.18.0/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
     sudo chmod +x /usr/local/bin/docker-compose
else
     echo "Docker-compose is installed."
fi

# Checking if go is installed.
GO_PATH="/usr/local/go"
if [ -d "$GO_PATH" ]; then
  # Control will enter here if $DIRECTORY exists.
   echo "Go is installed."
else
   echo "Go is not installed. Installing go..."
   wget https://dl.google.com/go/go1.10.1.linux-amd64.tar.gz
   sudo tar -C /usr/local -xzf go1.10.1.linux-amd64.tar.gz
   rm go1.10.1.linux-amd64.tar.gz
fi

# Checking if go is present.
path_go=$(echo $GOPATH)
length_path_go=$(expr length "$path_go")
if [ $length_path_go = 0 ]; then
     echo "GOPATH is not set. Setting GOPATH..."     
     #export PATH=$PATH:/usr/local/go/bin
     #export GOPATH=$GOPATH:/usr/local/go/bin
     #GOPATH="/usr/local/go/bin"
     #exec /bin/bash
     source "exportGO.sh"
else
     echo "GOPATH is already set."
fi
sudo chmod -R 777 "/usr/local/go"

# Checking is clairctl is installed.
CLAIR_CTL_PATH="/usr/local/go/bin/src/github.com/jgsqware/clairctl"
if [ -d "$CLAIR_CTL_PATH" ]; then
  # Control will enter here if $DIRECTORY exists.
   echo "Clairctl exists."
else
   echo "Clairctl does not exist. Please set up clairctl."

   # Creating needed hierarchy for clairctl.
   if [ ! -d $GOPATH/src/github.com/jgsqware/clairctl ]; then
       echo "Entered here"
       mkdir -p -m 777 $GOPATH/src;
       mkdir -p -m 777 $GOPATH/src/github.com;
       mkdir -p -m 777 $GOPATH/src/github.com/jgsqware;
   fi

   
   wget https://github.com/jgsqware/clairctl/archive/master.zip
   unzip master.zip -d $GOPATH/src/github.com/jgsqware
   rm master.zip
   mv $GOPATH/src/github.com/jgsqware/clairctl-master $GOPATH/src/github.com/jgsqware/clairctl
fi

# Installing graphviz
python3 -c "import graphviz" &> /dev/null
if [ "$?" = "1" ]; then
    echo "Graphviz has not been installed. Installing Graphviz..."
    sudo pip3 install graphviz
else
    echo "Graphviz is installed."
fi

sudo apt-get install graphviz

# Installing yaml
python3 -c "import yaml" &> /dev/null
if [ "$?" = "1" ]; then
    echo "Pyyaml has not been installed. Installing Pyyaml..."
    sudo pip3 install pyyaml
else
    echo "Pyyaml is installed."
fi

# Installing networkx
python3 -c "import networkx" &> /dev/null
if [ "$?" = "1" ]; then
    echo "Networkx has not been installed. Installing Networkx..."
    sudo pip3 install networkx
else
    echo "Networkx is installed."
fi

# Installing numpy
python3 -c "import numpy" &> /dev/null
if [ "$?" = "1" ]; then
    echo "Numpy has not been installed. Installing Numpy..."
    sudo pip3 install numpy
else
    echo "Numpy is installed."
fi

# Installing unzip
sudo apt-get install unzip

# Creating examples
# Atsea
unzip examples/atsea-sample-shop-app-master.zip -d examples
sudo chmod 777 examples/atsea-sample-shop-app-master
mv examples/atsea-sample-shop-app-master examples/atsea

# Javaee
unzip examples/javaee-demo-master.zip -d examples
sudo chmod 777 examples/javaee-demo-master
mv examples/javaee-demo-master examples/javaee

# Samba
unzip examples/exploit-CVE-2017-7494-master -d examples
sudo chmod 777 examples/exploit-CVE-2017-7494-master
mv examples/exploit-CVE-2017-7494-master examples/example/samba

# Phpmailer
unzip examples/exploit-CVE-2016-10033-master -d examples
sudo chmod 777 examples/exploit-CVE-2016-10033-master
mv examples/exploit-CVE-2016-10033-master examples/example/phpmailer

#sudo groupadd docker
#sudo usermod -aG docker $(whoami)
#sudo service docker start

# Checks if the number of arguments is correct.
if  [ $# == 2 ]; then
    echo "The dependencies are installed. Starting the attack graph generator."
    echo ""
    sudo python3 main.py $1 $2
else
    echo "You need to provide two arguments. First argument should be the folder for the project, and the second one should be the goal container."
fi

if  [ $1 == "--help" ]; then
    echo "Option --help turned on"
    echo "Command: ./attack-graph-generator.sh <example-folder-path> <goal-container>"
    echo "<example-folder-path> is the folder that we want to analyze."
    echo "<goal-container> is the name of the docker that the attacker wants to control."
fi



