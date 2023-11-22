# watcher

Monitor Linux systems in real time using bpftrace and visualize results on the web interface
Disclaimer: This is CTF level code, for now. But still very fast

## Usage

Configure Dockerfile then run:

```
docker build . -t watcher
docker run -v $(pwd)/target:/watcher/target -p8900:8900 watcher
# run binary from target/release/watcher on prod machine and capture the logs
```

It's recommended to use Caddy for https configuration:
```
watcher.your-domain.com {
	reverse_proxy localhost:8900
}
```