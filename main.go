package main

import (
	"encoding/base64"
	"flag"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/tvdburgt/go-argon2"
	cryptoargon2 "golang.org/x/crypto/argon2"
	"log"
	"net/http"
	"regexp"
	"time"

	matthewhartstonge "github.com/matthewhartstonge/argon2"
)

//"github.com/baenv/go-argon2"

var (
	enableMetrics  = flag.Bool("enable-metrics", false, "Enable metrics collection and server")
	metricsPort    = flag.String("metrics-addr", "127.0.0.1:8085", "metrics server address")
	iterations     = flag.Int("iterations", 1, "number of iterations (t_cost)")
	memory         = flag.Int("memory", 1024, "memory usage in KiB (m_cost)")
	memoryIncrease = flag.Int("memory-increase", 0, "increase the memory usage in KiB every 10 seconds")
	parallelism    = flag.Int("parallelism", 1, "number of parallel threads")
	hashLen        = flag.Int("hash-len", 64, "desired hash output length")
	verbose        = flag.Bool("verbose", false, "verbose")

	argon2Lib = flag.String("argon2-lib", "libargon2", "argon2 library to use (libargon2, cryptoargon2, or goargon2)")

	argon2Memory       prometheus.Gauge
	argon2Transactions prometheus.Counter
	loop               = 0
	ctx                *argon2.Context

	salt     = []byte("XEN10082022XEN")
	password = []byte("0000da975bd6ec3aa878dadc395943619d23407371bc15066c1505ef23203d871633c687a9e5e89f5fc7fb61f05e1ff4ec49ecee28577c5143711185afe2d5a5")
)

func cryptoArgon2() {
	for {
		hash := cryptoargon2.IDKey(password, salt, uint32(*iterations), uint32(*memory), uint8(*parallelism), uint32(*hashLen))
		if *verbose {
			// Base64 encode the salt and hashed password.
			b64Salt := base64.RawStdEncoding.EncodeToString(salt)
			b64Hash := base64.RawStdEncoding.EncodeToString(hash)
			log.Printf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", cryptoargon2.Version, *memory, *iterations, *parallelism, b64Salt, b64Hash)
		}

		loop++
	}
}

func libargon2() {
	for {
		hash, err := argon2.HashEncoded(ctx, password, salt)
		if err != nil {
			panic(err)
		}

		if *verbose {
			log.Printf("hash: %s\n", hash)
		}
		loop++
	}
}

func matthewhartstongeArgon2() {
	for {
		argon := matthewhartstonge.Config{
			HashLength:  uint32(*hashLen),
			MemoryCost:  uint32(*memory),
			TimeCost:    uint32(*iterations),
			Parallelism: uint8(*parallelism),
			Mode:        matthewhartstonge.ModeArgon2id,
			Version:     matthewhartstonge.Version13,
		}

		raw, err := argon.Hash(password, salt)
		if err != nil {
			panic(err)
		}

		if *verbose {
			log.Printf(string(raw.Encode()))
		}

		loop++
	}
}

func metrics() {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewBuildInfoCollector())
	reg.MustRegister(collectors.NewGoCollector(
		collectors.WithGoCollectorRuntimeMetrics(collectors.GoRuntimeMetricsRule{Matcher: regexp.MustCompile("/.*")}),
	))

	argon2Memory = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "argon2",
		Name:      "memory",
		Help:      "memory usage in KiB (m_cost)",
	})
	reg.MustRegister(argon2Memory)

	argon2Transactions = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "argon2",
		Name:      "transactions",
		Help:      "nuber of transactions",
	})
	reg.MustRegister(argon2Transactions)

	http.Handle("/metrics", promhttp.HandlerFor(
		reg,
		promhttp.HandlerOpts{
			EnableOpenMetrics: true,
		},
	))
	log.Fatal(http.ListenAndServe(*metricsPort, nil))
}

func main() {
	flag.Parse()

	if *enableMetrics {
		go metrics()
	}

	ctx = &argon2.Context{
		Iterations:  *iterations,
		Memory:      *memory,
		Parallelism: *parallelism,
		HashLen:     *hashLen,
		Mode:        argon2.ModeArgon2id,
		Version:     argon2.Version13,
	}

	if *argon2Lib == "libargon2" {
		go libargon2()
	} else if *argon2Lib == "cryptoargon2" {
		go cryptoArgon2()
	} else if *argon2Lib == "matthewhartstonge" {
		go matthewhartstongeArgon2()
	} else {
		log.Fatal("Invalid argon2 library")
	}

	for {
		time.Sleep(10 * time.Second)

		log.Printf("tps=%d memory=%d", loop/10, ctx.Memory)
		ctx.Memory += *memoryIncrease

		if *enableMetrics && argon2Transactions != nil && argon2Memory != nil {
			argon2Transactions.Add(float64(loop))
			argon2Memory.Set(float64(*memory))
		}

		loop = 0
	}
}
