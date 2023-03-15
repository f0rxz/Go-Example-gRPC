SRV_NAME=srvnetvuln
CLI_NAME=clinetvuln
SRV=./cmd/server
CLI=./cmd/client

LDFLAGS=-ldflags="-s -w"

all: build

build:
	go build ${LDFLAGS} -o ${SRV_NAME} ${SRV}
	go build ${LDFLAGS} -o ${CLI_NAME} ${CLI}

lint:
	golangci-lint run ./...

# TODO add tests
test:
	go test ./...
