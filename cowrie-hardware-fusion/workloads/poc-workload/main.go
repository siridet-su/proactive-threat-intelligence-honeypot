package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	maxDuration       = 180 * time.Second
	maxWorkers        = 4
	maxRequestsPerSec = 200
	maxWorkIterations = 20000
)

type configuration struct {
	mode              string
	duration          time.Duration
	workers           int
	dutyPercent       int
	dutyPeriod        time.Duration
	requestsPerSecond int
	workIterations    int
	seed              uint64
}

type summary struct {
	SchemaVersion string `json:"schema_version"`
	Mode          string `json:"mode"`
	ElapsedMS     int64  `json:"elapsed_ms"`
	Operations    uint64 `json:"operations"`
	Errors        uint64 `json:"errors"`
}

func parseConfiguration(arguments []string) (configuration, error) {
	flags := flag.NewFlagSet("poc-workload", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	config := configuration{}
	flags.StringVar(&config.mode, "mode", "", "fixed workload mode: compute or service")
	flags.DurationVar(&config.duration, "duration", 30*time.Second, "bounded run duration")
	flags.IntVar(&config.workers, "workers", 1, "bounded worker count")
	flags.IntVar(&config.dutyPercent, "duty-percent", 100, "compute duty cycle percent")
	flags.DurationVar(&config.dutyPeriod, "duty-period", 100*time.Millisecond, "compute duty period")
	flags.IntVar(&config.requestsPerSecond, "requests-per-second", 10, "total local request rate")
	flags.IntVar(&config.workIterations, "work-iterations", 1000, "hash iterations per request")
	flags.Uint64Var(&config.seed, "seed", 20260902, "deterministic workload seed")
	if err := flags.Parse(arguments); err != nil {
		return configuration{}, err
	}
	if flags.NArg() != 0 {
		return configuration{}, errors.New("positional arguments are not accepted")
	}
	if config.mode != "compute" && config.mode != "service" {
		return configuration{}, errors.New("mode must be compute or service")
	}
	if config.duration < time.Second || config.duration > maxDuration {
		return configuration{}, fmt.Errorf("duration must be between 1s and %s", maxDuration)
	}
	if config.workers < 1 || config.workers > maxWorkers {
		return configuration{}, fmt.Errorf("workers must be between 1 and %d", maxWorkers)
	}
	if config.dutyPercent < 1 || config.dutyPercent > 100 {
		return configuration{}, errors.New("duty-percent must be between 1 and 100")
	}
	if config.dutyPeriod < 50*time.Millisecond || config.dutyPeriod > time.Second {
		return configuration{}, errors.New("duty-period must be between 50ms and 1s")
	}
	if config.requestsPerSecond < 1 || config.requestsPerSecond > maxRequestsPerSec {
		return configuration{}, fmt.Errorf("requests-per-second must be between 1 and %d", maxRequestsPerSec)
	}
	if config.workIterations < 1 || config.workIterations > maxWorkIterations {
		return configuration{}, fmt.Errorf("work-iterations must be between 1 and %d", maxWorkIterations)
	}
	return config, nil
}

func hashWork(seed uint64, worker int, operations *atomic.Uint64) {
	buffer := make([]byte, 40)
	binary.LittleEndian.PutUint64(buffer[0:8], seed)
	binary.LittleEndian.PutUint64(buffer[8:16], uint64(worker))
	for index := 0; index < 4096; index++ {
		digest := sha256.Sum256(buffer)
		copy(buffer[8:], digest[:])
	}
	operations.Add(1)
}

func runCompute(ctx context.Context, config configuration) (uint64, uint64) {
	var operations atomic.Uint64
	var workers sync.WaitGroup
	onDuration := time.Duration(int64(config.dutyPeriod) * int64(config.dutyPercent) / 100)
	offDuration := config.dutyPeriod - onDuration
	for worker := 0; worker < config.workers; worker++ {
		workers.Add(1)
		go func(workerID int) {
			defer workers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				cycleStarted := time.Now()
				for time.Since(cycleStarted) < onDuration {
					hashWork(config.seed, workerID, &operations)
					if ctx.Err() != nil {
						return
					}
				}
				if offDuration > 0 {
					timer := time.NewTimer(offDuration)
					select {
					case <-ctx.Done():
						timer.Stop()
						return
					case <-timer.C:
					}
				}
			}
		}(worker)
	}
	workers.Wait()
	return operations.Load(), 0
}

func requestWork(seed uint64, iterations int) {
	buffer := make([]byte, 32)
	binary.LittleEndian.PutUint64(buffer[0:8], seed)
	for index := 0; index < iterations; index++ {
		digest := sha256.Sum256(buffer)
		copy(buffer, digest[:])
	}
}

func runService(ctx context.Context, config configuration) (uint64, uint64, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, 0, fmt.Errorf("create loopback listener: %w", err)
	}
	var operations atomic.Uint64
	var failures atomic.Uint64
	server := &http.Server{
		ReadHeaderTimeout: time.Second,
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path != "/work" {
				http.NotFound(writer, request)
				return
			}
			requestWork(config.seed+operations.Load(), config.workIterations)
			operations.Add(1)
			writer.WriteHeader(http.StatusNoContent)
		}),
	}
	serverErrors := make(chan error, 1)
	go func() {
		errorValue := server.Serve(listener)
		if errorValue != nil && !errors.Is(errorValue, http.ErrServerClosed) {
			serverErrors <- errorValue
		}
		close(serverErrors)
	}()

	transport := &http.Transport{
		Proxy:               nil,
		DisableKeepAlives:   false,
		MaxIdleConns:        config.workers,
		MaxIdleConnsPerHost: config.workers,
	}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	requestInterval := time.Second / time.Duration(config.requestsPerSecond)
	ticker := time.NewTicker(requestInterval)
	defer ticker.Stop()
	var clients sync.WaitGroup
	requestSlots := make(chan struct{}, config.workers)
	for {
		select {
		case <-ctx.Done():
			shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 2*time.Second)
			_ = server.Shutdown(shutdownContext)
			cancelShutdown()
			clients.Wait()
			transport.CloseIdleConnections()
			if serverError := <-serverErrors; serverError != nil {
				return operations.Load(), failures.Load(), serverError
			}
			return operations.Load(), failures.Load(), nil
		case <-ticker.C:
			select {
			case requestSlots <- struct{}{}:
				clients.Add(1)
				go func() {
					defer clients.Done()
					defer func() { <-requestSlots }()
					request, requestError := http.NewRequestWithContext(
						ctx,
						http.MethodGet,
						"http://"+listener.Addr().String()+"/work",
						nil,
					)
					if requestError != nil {
						failures.Add(1)
						return
					}
					response, requestError := client.Do(request)
					if requestError != nil {
						if ctx.Err() == nil {
							failures.Add(1)
						}
						return
					}
					_ = response.Body.Close()
					if response.StatusCode != http.StatusNoContent {
						failures.Add(1)
					}
				}()
			default:
				failures.Add(1)
			}
		}
	}
}

func run(arguments []string) error {
	config, err := parseConfiguration(arguments)
	if err != nil {
		return err
	}
	rootContext, stopSignals := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stopSignals()
	ctx, cancel := context.WithTimeout(rootContext, config.duration)
	defer cancel()
	started := time.Now()
	var operations uint64
	var failures uint64
	if config.mode == "compute" {
		operations, failures = runCompute(ctx, config)
	} else {
		operations, failures, err = runService(ctx, config)
		if err != nil {
			return err
		}
	}
	result := summary{
		SchemaVersion: "poc_workload_summary.v1",
		Mode:          config.mode,
		ElapsedMS:     time.Since(started).Milliseconds(),
		Operations:    operations,
		Errors:        failures,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(result)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}
