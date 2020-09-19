FROM golang:1.15.2-alpine3.12

WORKDIR /go/src/app
COPY . .

RUN go get -d -v ./...
RUN go install -v ./...

CMD ["dalfox"]
