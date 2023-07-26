# watcher

Monitor Linux systems in real time using bpftrace and visualize results on the web interface
Disclaimer: This is CTF level code, for now. But still very fast

## Usage

```
Run backend on the webserver. Redis instance needs to be running at 6379.
Compile and run watcher on the target server. Make sure to set the URL correctly.
```

## Build

```
LITCRYPT_ENCRYPT_KEY=your_secret_key cargo build --release
```
