#!/bin/bash

# Установка protoc
if [ "$(uname)" == "Darwin" ]; then
    # macOS
    brew install protobuf
elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
    # Linux
    sudo apt-get update
    sudo apt-get install -y protobuf-compiler
elif [ "$(expr substr $(uname -s) 1 10)" == "MINGW32_NT" ]; then
    # Windows
    echo "Для Windows установите protoc вручную с https://github.com/protocolbuffers/protobuf/releases"
fi

# Установка Go плагинов для protoc
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Добавление путей в PATH
export PATH="$PATH:$(go env GOPATH)/bin"

# Генерация кода
./generate_proto.sh 