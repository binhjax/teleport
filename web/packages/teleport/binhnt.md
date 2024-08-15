export VITE_HTTPS_CERT=$(pwd)/../../certs/server.crt
export VITE_HTTPS_KEY=$(pwd)/../../certs/server.key
export PROXY_TARGET=https://localhost:3080/web

yarn run start 