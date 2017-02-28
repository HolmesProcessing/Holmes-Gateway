FROM golang:alpine

# create folder
RUN mkdir -p $GOPATH/src/Holmes-Processing/Holmes-Gateway
WORKDIR $GOPATH/src/Holmes-Processing/Holmes-Gateway

# get go dependencies
RUN apk add --no-cache \
		git \
	&& rm -rf /var/cache/apk/*

# add the files to the container
COPY main.go $GOPATH/src/Holmes-Processing/Holmes-Gateway
RUN go get ./...

# build
RUN go build

EXPOSE 8080 8090

COPY config $GOPATH/src/Holmes-Processing/Holmes-Gateway/config

CMD sh -c "./Holmes-Gateway --master 2>&1 | tee master-gateway.log & ./Holmes-Gateway 2>&1 | tee gateway.log"
