detect_version() {
    local version="${DOKPLOY_VERSION:-latest}"
    echo "$version"
}
is_proxmox_lxc() {
    if [ -n "$container" ] && [ "$container" = "lxc" ]; then
        return 0
    fi
    if grep -q "container=lxc" /proc/1/environ 2>/dev/null; then
        return 0
    fi
    return 1
}

install_dokploy() {
    VERSION_TAG=$(detect_version)
    DOCKER_IMAGE="dokploy/dokploy:${VERSION_TAG}"
    echo "Installing Dokploy version: ${VERSION_TAG}"
    if [ "$(id -u)" != "0" ]; then
        echo "This script must be run as root" >&2
        exit 1
    fi
    if [ "$(uname)" = "Darwin" ]; then
        echo "This script must be run on Linux" >&2
        exit 1
    fi
    if [ -f /.dockerenv ]; then
        echo "This script must be run on Linux" >&2
        exit 1
    fi
    if ss -tulnp | grep ':80 ' >/dev/null; then
        echo "Error: something is already running on port 80" >&2
        exit 1
    fi
    if ss -tulnp | grep ':443 ' >/dev/null; then
        echo "Error: something is already running on port 443" >&2
        exit 1
    fi
    if ss -tulnp | grep ':10000 ' >/dev/null; then
        echo "Error: something is already running on port 10000" >&2
        echo "Dokploy requires port 10000 to be available. Please stop any service using this port." >&2
        exit 1
    fi

    command_exists() {
      command -v "$@" > /dev/null 2>&1
    }

    if command_exists docker; then
      echo "Docker already installed"
    else
      curl -sSL https://get.docker.com | sh -s -- --channel stable
    fi

    endpoint_mode="--endpoint-mode dnsrr"
    docker swarm leave --force 2>/dev/null

    get_ip() {
        local ip=""
        ip=$(curl -4s --connect-timeout 5 https://ifconfig.io 2>/dev/null)
        if [ -z "$ip" ]; then
            ip=$(curl -4s --connect-timeout 5 https://icanhazip.com 2>/dev/null)
        fi
        if [ -z "$ip" ]; then
            ip=$(curl -4s --connect-timeout 5 https://ipecho.net/plain 2>/dev/null)
        fi
        if [ -z "$ip" ]; then
            ip=$(curl -6s --connect-timeout 5 https://ifconfig.io 2>/dev/null)
            if [ -z "$ip" ]; then
                ip=$(curl -6s --connect-timeout 5 https://icanhazip.com 2>/dev/null)
            fi
            if [ -z "$ip" ]; then
                ip=$(curl -6s --connect-timeout 5 https://ipecho.net/plain 2>/dev/null)
            fi
        fi

        if [ -z "$ip" ]; then
            echo "Error: Could not determine server IP address automatically (neither IPv4 nor IPv6)." >&2
            echo "Please set the ADVERTISE_ADDR environment variable manually." >&2
            echo "Example: export ADVERTISE_ADDR=<your-server-ip>" >&2
            exit 1
        fi

        echo "$ip"
    }

    get_private_ip() {
        ip addr show | awk '
        /inet (10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/ {
            split($2, a, "/");
            print a[1];
            exit;
        }'
    }

    advertise_addr="${ADVERTISE_ADDR:-$(get_private_ip)}"

    if [ -z "$advertise_addr" ]; then
        echo "ERROR: We couldn't find a private IP address."
        echo "Please set the ADVERTISE_ADDR environment variable manually."
        echo "Example: export ADVERTISE_ADDR=192.168.1.100"
        exit 1
    fi
    echo "Using advertise address: $advertise_addr"
    swarm_init_args="${DOCKER_SWARM_INIT_ARGS:-}"
    
    if [ -n "$swarm_init_args" ]; then
        echo "Using custom swarm init arguments: $swarm_init_args"
        docker swarm init --advertise-addr $advertise_addr $swarm_init_args
    else
        docker swarm init --advertise-addr $advertise_addr
    fi
    
     if [ $? -ne 0 ]; then
        echo "Error: Failed to initialize Docker Swarm" >&2
        exit 1
    fi

    echo "Swarm initialized"

    docker network rm -f dokploy-network 2>/dev/null
    docker network create --driver overlay --attachable dokploy-network

    echo "Network created"

    mkdir -p /etc/dokploy

    chmod 777 /etc/dokploy
    #===============================================
    # Postgres
    #===============================================
    #docker pull postgres:18
    docker service create \
    --name dokploy-postgres \
    --constraint 'node.role==manager' \
    --network dokploy-network \
    --restart-condition on-failure \
    --env POSTGRES_USER=dokploy \
    --env POSTGRES_DB=dokploy \
    --env POSTGRES_PASSWORD=amukds4wi9001583845717ad2 \
    --mount type=volume,source=dokploy-postgres,target=/var/lib/postgresql/data \
    $endpoint_mode \
    postgres:17-alpine

    #===============================================
    # Redis-Valkey
    #===============================================
    #docker pull valkey/valkey:9-alpine
    docker service create \
    --name dokploy-redis \
    --constraint 'node.role==manager' \
    --network dokploy-network \
    --restart-condition on-failure \
    --mount type=volume,source=dokploy-redis,target=/data \
    $endpoint_mode \
    valkey/valkey:9-alpine

    release_tag_env=""
    if [ "$VERSION_TAG" != "latest" ]; then
        release_tag_env="-e RELEASE_TAG=$VERSION_TAG"
    fi
    #===============================================
    # Dokploy
    #===============================================
    docker service create \
      --name dokploy \
      --replicas 1 \
      --network dokploy-network \
      --restart-condition on-failure \
      --mount type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock \
      --mount type=bind,source=/etc/dokploy,target=/etc/dokploy \
      --mount type=volume,source=dokploy,target=/root/.docker \
      --publish published=10000,target=3000,mode=host \
      --update-parallelism 1 \
      --update-order stop-first \
      --constraint 'node.role == manager' \
      $endpoint_mode \
      $release_tag_env \
      --env ADVERTISE_ADDR=$advertise_addr \
      $DOCKER_IMAGE

    sleep 4
    #===============================================
    # Traefik
    #===============================================
    #docker pull traefik:v3.7.1
       docker service create \
         --name dokploy-traefik \
         --constraint 'node.role==manager' \
         --network dokploy-network \
         --mount type=bind,source=/etc/dokploy/traefik/traefik.yml,target=/etc/traefik/traefik.yml \
         --mount type=bind,source=/etc/dokploy/traefik/dynamic,target=/etc/dokploy/traefik/dynamic \
         --mount type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock \
         --publish mode=host,published=443,target=443 \
         --publish mode=host,published=80,target=80 \
         --update-order stop-first \
         --restart-condition on-failure \
         --publish mode=host,published=443,target=443,protocol=udp \
         traefik:v3.7.1

    GREEN="\033[0;32m"
    YELLOW="\033[1;33m"
    BLUE="\033[0;34m"
    NC="\033[0m"

    format_ip_for_url() {
        local ip="$1"
        if echo "$ip" | grep -q ':'; then
            echo "[${ip}]"
        else
            echo "${ip}"
        fi
    }

    public_ip="${ADVERTISE_ADDR:-$(get_ip)}"
    formatted_addr=$(format_ip_for_url "$public_ip")
    echo ""
    printf "${GREEN}Congratulations, Dokploy is installed!${NC}\n"
    printf "${BLUE}Wait 15 seconds for the server to start${NC}\n"
    printf "${YELLOW}Please go to http://${formatted_addr}:10000${NC}\n\n"
}

update_dokploy() {
    VERSION_TAG=$(detect_version)
    DOCKER_IMAGE="dokploy/dokploy:${VERSION_TAG}"
    
    echo "Updating Dokploy to version: ${VERSION_TAG}"
    docker pull $DOCKER_IMAGE
    docker service update --image $DOCKER_IMAGE dokploy
    echo "Dokploy has been updated to version: ${VERSION_TAG}"
}

if [ "$1" = "update" ]; then
    update_dokploy
else
    install_dokploy
fi
