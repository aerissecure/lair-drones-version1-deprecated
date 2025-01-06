function ddrone-burp() {
    PROJECTID="$1"
    FILE=$(realpath $2)
    if [ ! -f $FILE ]; then
        echo "File '$FILE' does not exist."
        return 1
    fi
    shift 2
    echo "Docker Command: drone-burp $PROJECTID /data$FILE --include-informational $@"
    docker run --rm --network host -v "/:/data" -e DRONE_DEBUG="${DRONE_DEBUG}" -e MONGO_URL="${MONGO_URL}" lair-drones-python2 unbuffer drone-burp $PROJECTID "/data$FILE" --include-informational $@
}

function ddrone-nessus() {
    PROJECTID="$1"
    FILE=$(realpath $2)
    if [ ! -f $FILE ]; then
        echo "File '$FILE' does not exist."
        return 1
    fi
    shift 2
    echo "Docker Command: drone-nessus $PROJECTID /data$FILE --include-informational --min-note-severity=0 $@"
    docker run --rm --network host -v "/:/data" -e DRONE_DEBUG="${DRONE_DEBUG}" -e MONGO_URL="${MONGO_URL}" lair-drones-python2 unbuffer drone-nessus $PROJECTID "/data$FILE" --include-informational --min-note-severity=0 $@
}

function ddrone-nessus-without-informational() {
    PROJECTID="$1"
    FILE=$(realpath $2)
    if [ ! -f $FILE ]; then
        echo "File '$FILE' does not exist."
        return 1
    fi
    shift 2
    echo "Docker Command: drone-nessus $PROJECTID /data$FILE $@"
    docker run --rm --network host -v "/:/data" -e DRONE_DEBUG="${DRONE_DEBUG}" -e MONGO_URL="${MONGO_URL}" lair-drones-python2 unbuffer drone-nessus $PROJECTID "/data$FILE" $@
}

function ddrone-nmap() {
    PROJECTID="$1"
    FILE=$(realpath $2)
    if [ ! -f $FILE ]; then
        echo "File '$FILE' does not exist."
        return 1
    fi
    shift 2
    echo "Docker Command: drone-nmap $PROJECTID /data$FILE $@"
    docker run --rm --network host -v "/:/data" -e DRONE_DEBUG="${DRONE_DEBUG}" -e MONGO_URL="${MONGO_URL}" lair-drones-python2 unbuffer drone-nmap $PROJECTID "/data$FILE" $@
}

function ddrone-wpscan-sum() {
    PROJECTID="$1"
    FILE=$(realpath $2)
    if [ ! -f $FILE ]; then
        echo "File '$FILE' does not exist."
        return 1
    fi
    shift 2
    echo "Docker Command: drone-wpscan-sum $PROJECTID /data$FILE $@"
    docker run --rm --network host -v "/:/data" -e DRONE_DEBUG="${DRONE_DEBUG}" -e MONGO_URL="${MONGO_URL}" lair-drones-python2 unbuffer drone-wpscan-sum $PROJECTID "/data$FILE" $@
}

function ddrone-wpscan() {
    PROJECTID="$1"
    FILE=$(realpath $2)
    if [ ! -f $FILE ]; then
        echo "File '$FILE' does not exist."
        return 1
    fi
    shift 2
    echo "Docker Command: drone-wpscan $PROJECTID /data$FILE $@"
    docker run --rm --network host -v "/:/data" -e DRONE_DEBUG="${DRONE_DEBUG}" -e MONGO_URL="${MONGO_URL}" lair-drones-python2 unbuffer drone-wpscan $PROJECTID "/data$FILE" $@
}

function ddrone-raw() {
    PROJECTID="$1"
    FILE=$(realpath $2)
    if [ ! -f $FILE ]; then
        echo "File '$FILE' does not exist."
        return 1
    fi
    shift 2
    echo "Docker Command: drone-raw $PROJECTID /data$FILE $@"
    docker run --rm --network host -v "/:/data" -e DRONE_DEBUG="${DRONE_DEBUG}" -e MONGO_URL="${MONGO_URL}" lair-drones-python2 unbuffer drone-raw $PROJECTID "/data$FILE" $@
}