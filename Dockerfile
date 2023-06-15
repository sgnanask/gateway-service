## We specify the base image we need for our
## go application
FROM  golang:1.20.5-alpine

## We specify that we now wish to execute 
## any further commands inside our /app
## directory
WORKDIR /app

## Add this go mod download command to pull in any dependencies
COPY go.* ./
RUN go mod download

COPY *.go ./

## we run go build to compile the binary
## executable of our Go program
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o server .

## Our start command which kicks off
## our newly created binary executable
CMD [ "/app/server" ]