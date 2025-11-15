# TODO

docker run --rm -it \
  -v "$PWD":/workspace \
  -w /workspace --entrypoint sh \
  -p 8080:80 \
  -p 8443:443 -e RUST_BACKTRACE=full -e RUST_LOG=debug \
  patrostkowski/sozu:latest

strace sozu --config /etc/sozu/config.toml start

GOOS=linux CGO_ENABLED=0 go build example/main.go