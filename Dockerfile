# Use an older version of Debian where Python 2 is still available
FROM debian:buster

# Update the package list
RUN apt-get update

# Install Python 2
RUN apt-get install -y python

# Install wget and other necessary tools
RUN apt-get install -y wget expect

# Download get-pip script
RUN wget https://bootstrap.pypa.io/pip/2.7/get-pip.py

# Install pip for Python 2
RUN python get-pip.py

# Install Git
RUN apt-get install -y git

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy the local code to the container
COPY . .

# Install dependencies and package
RUN pip install . && \
    pip install requests && \
    python setup.py install
