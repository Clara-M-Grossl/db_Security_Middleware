FROM golang:1.21

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o middleware ./cmd/middleware

EXPOSE 8000

CMD ["./middleware"]
