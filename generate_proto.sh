#!/bin/bash

# Генерация кода для AuthService
protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    AuthService/proto/auth.proto

# Генерация кода для ForumService
protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    ForumService/proto/forum.proto 