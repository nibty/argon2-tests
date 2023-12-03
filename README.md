# Argon2 Tests

Some tests for the Argon2 password hashing algorithm using GO and Python.

```shell
# https://github.com/tvdburgt/go-argon2
go run main.go --memory 262144 --argon2-lib libargon2

# https://pkg.go.dev/golang.org/x/crypto/argon2
go run main.go --memory 262144 --argon2-lib crypto/argon2

# https://github.com/matthewhartstonge/argon2
go run main.go --memory 262144 --argon2-lib matthewhartstonge
```

> all options
```shell
./main --help
Usage of ./main:
  -argon2-lib string
    	argon2 library to use (libargon2, cryptoargon2, or goargon2) (default "libargon2")
  -enable-metrics
    	Enable metrics collection and server
  -hash-len int
    	desired hash output length (default 64)
  -iterations int
    	number of iterations (t_cost) (default 1)
  -memory int
    	memory usage in KiB (m_cost) (default 1024)
  -memory-increase int
    	increase the memory usage in KiB every 10 seconds
  -metrics-addr string
    	metrics server address (default "127.0.0.1:8085")
  -parallelism int
    	number of parallel threads (default 1)
  -verbose
    	verbose
```
