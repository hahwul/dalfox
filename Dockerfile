FROM golang:1.14
MAINTAINER hahwul@gmail.com

WORKDIR /go/src/app
COPY . .

RUN go get -d -v ./...
RUN go install -v ./...

CMD ["dalfox"]
