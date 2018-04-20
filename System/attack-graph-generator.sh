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

path_pip=$(which pip3)
length_path_pip=$(expr length "$path_pip")
if [ "$length_path_pip3" = "0" ]; then
     echo "Pip3 is not installed."
     sudo apt-get install python3-pip
else
     echo "Pip3 is installed."
fi

# Checking if docker is installed.
path_docker=$(which docker)
length_path_docker=$(expr length "$path_docker")
if [ $length_path_docker = 0 ]; then
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
if [ $length_path_docker_compose = 0 ]; then
     echo "Docker-compose is not installed."
     sudo $(apt-get -y install python-pip)
     sudo $(pip install docker-compose)
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
echo $length_path_go
if [ $length_path_go = 0 ]; then
     echo "GOPATH is not set. Setting GOPATH..."
     
     export PATH=$PATH:/usr/local/go/bin
     export GOPATH=$GOPATH:/usr/local/go/bin
     GOPATH="/usr/local/go/bin"
     exec /bin/bash
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
   exit 1
fi

# Installing graphviz
sudo pip3 install graphviz
sudo apt-get install graphviz

# Installing yaml
sudo pip3 install pyyaml

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



