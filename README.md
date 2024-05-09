## This library is deprecated and should only be used for Lair v1

##Lair Drones##
Lair takes a different approach to uploading, parsing, and ingestion of automated tool output (xml). We push this work off onto client side scripts called drones. These drones connect directly to the database. To use them all you have to do is export an environment variable "MONGO_URL". This variable is probably going to be the same you used for installation


        export MONGO_URL='mongodb://username:password@ip:27017/lair?ssl=true'

With the environment variable set you will need a project id to import data. You can grab this from the upper right corner of the lair dashboard next to the project name. You can now run any drones.


You can install the drones to PATH with pip

        pip install lairdrone-<version>.tar.gz


#### drone-nmap options

drone-nmap is now configurable to accept both -oX and -oG report formats. To have drone-nmap gather information from grepable nmap report files, use:

        drone-nmap <pid> /path/to/nmap-grepable.txt grep

To import XML reports, use:

        drone-nmap <pid> /path/to/nmap.xml xml

or

        drone-nmap <pid> /path/to/nmap.xml

drone-nmap will always default the report format to XML.

# Installation in a Docker Environment

## Build the Docker Container

To build the Docker image, run the following command:

```
docker build -t lair-drones-python2 .
```

## Configuration in `.zshrc`

### Export MONGO_URL Connection String

Add the following line to your `.zshrc` file to set up the MongoDB connection string for the application:

```
export MONGO_URL='mongodb://username:password@ip:27017/lair?ssl=true'
```

### Add Function to Run Docker Container

Incorporate this function into your `.zshrc` file to enable running the Docker container with the necessary configurations:

```
function drone-run() {
    # First, determine the program to run and the file path
    local program="$1"
    shift  # Remove the first argument which is the program name

    # Determine the path of the last argument which should be the file path
    local file="${@: -1}"  # Get the last argument as the file

    # Determine the directory based on the file path
    if [[ "$file" == /* ]]; then
        file_dir=$(dirname "$file")
    elif [[ "$file" == ./* ]]; then
        # Handle relative path with ./
        file_dir=$(pwd)/$(dirname "$file")
        file_dir=${file_dir/.\//}  # Remove leading ./
    else
        # Handle file in the current directory or a simple relative path
        file_dir=$(pwd)
    fi

    # Check if the specified file exists
    if [[ ! -f "$file" ]]; then
        echo "Error: File $file does not exist."
        return 1  # Exit the function with an error
    fi

    echo "Mounting ${file_dir} to /data in container"
    echo "Accessing file as /data/$(basename "$file")"

    # Execute the Docker command, passing all remaining arguments
    docker run --rm --network host -v "${file_dir}:/data" -e MONGO_URL="${MONGO_URL}" lair-drones-python2 "$program" "${@:1:-1}" "/data/$(basename "$file")"
}
```

## Usage Examples

- Absolute path:

```
drone-run drone-burp aAZrpLuJ9TBHDfNtx /home/kali/file.xml
```

- Relative path:

```
drone-run drone-burp aAZrpLuJ9TBHDfNtx ./kali/file.xml
```

- File in the current directory:

```
drone-run drone-burp aAZrpLuJ9TBHDfNtx file.xml
```

### Running without script

```
docker run --rm --network host -v "$(pwd):/data" -e MONGO_URL="${MONGO_URL}" lair-drones-python2 drone-burp aYZrpLuJ9TBHDfNtx /data/test_export.xml
```



