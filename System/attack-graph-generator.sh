#!/bin/bash

echo ""
echo "Checking if dependencies are installed..."
# Checking if python is installed.
path_python=$(which python3)
length_path_python=$(expr length "$path_python")
if [ "$length_path_python3" = "0" ]; then
     echo "Python is not installed."
     sudo $(apt-get update)
     sudo $(apt-get install docker-ce)
else
     echo "Python is installed."
fi

# Checking if docker is installed.
path_docker=$(which docker)
length_path_docker=$(expr length "$path_docker")
if [ $length_path_docker = 0 ]; then
     echo "Docker is not installed."
     sudo $(apt-get update)
     sudo $(sudo apt-get install python3.6)
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

# Checking is clairctl is installed.
CLAIR_CTL_PATH="$HOME/golang/go/bin/src/github.com/jgsqware/clairctl"
if [ -d "$CLAIR_CTL_PATH" ]; then
  # Control will enter here if $DIRECTORY exists.
   echo "Clairctl exists."
else
   echo "Clairctl does not exist. Please set up clairctl."
   exit 1
fi

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



