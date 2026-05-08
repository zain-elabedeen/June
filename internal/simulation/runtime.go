package simulation

import (
	"api/internal/config"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	contextErrorType = "june.sim.error_type"
	contextMessage   = "june.sim.message"
)

type runtimeConfig struct {
	enabled            bool
	profile            string
	serviceName        string
	errorEvery         int
	latencyMs          int
	timeoutEvery       int
	dependencyEvery    int
	cpuBurnMs          int
	memoryMB           int
	crashAfterRequests int
	probeFailureEvery  int
}

// Runtime owns deterministic simulation counters and retained memory.
type Runtime struct {
	cfg          runtimeConfig
	requests     atomic.Uint64
	readyChecks  atomic.Uint64
	memoryMu     sync.Mutex
	memoryBlocks [][]byte
}

// New builds a simulation runtime from process configuration.
func New(cfg config.Config) *Runtime {
	runtimeCfg := runtimeConfig{
		enabled:            cfg.SimEnabled,
		profile:            normalizedProfile(cfg.SimProfile),
		serviceName:        firstNonEmpty(cfg.ServiceName, "june-api"),
		errorEvery:         cfg.SimErrorEvery,
		latencyMs:          cfg.SimLatencyMs,
		timeoutEvery:       cfg.SimTimeoutEvery,
		dependencyEvery:    cfg.SimDependencyEvery,
		cpuBurnMs:          cfg.SimCPUBurnMs,
		memoryMB:           cfg.SimMemoryMB,
		crashAfterRequests: cfg.SimCrashAfterRequests,
		probeFailureEvery:  cfg.SimProbeFailureEvery,
	}
	applyProfileDefaults(&runtimeCfg)
	return &Runtime{cfg: runtimeCfg}
}

// StructuredLogger emits one JSON request event per HTTP request.
func StructuredLogger(serviceName string) gin.HandlerFunc {
	serviceName = firstNonEmpty(serviceName, "june-api")
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		latencyMs := float64(time.Since(start).Microseconds()) / 1000.0
		status := c.Writer.Status()
		route := c.FullPath()
		if route == "" {
			route = c.Request.URL.Path
		}

		level := "info"
		if status >= http.StatusInternalServerError || len(c.Errors) > 0 {
			level = "error"
		}

		message := "request completed"
		if value, ok := c.Get(contextMessage); ok {
			message = fmt.Sprint(value)
		} else if len(c.Errors) > 0 {
			message = c.Errors.String()
		}

		event := map[string]any{
			"timestamp":   time.Now().UTC().Format(time.RFC3339Nano),
			"service":     serviceName,
			"level":       level,
			"method":      c.Request.Method,
			"route":       route,
			"path":        c.Request.URL.Path,
			"status_code": status,
			"latency_ms":  math.Round(latencyMs*100) / 100,
			"message":     message,
		}
		if value, ok := c.Get(contextErrorType); ok {
			event["error_type"] = fmt.Sprint(value)
		}

		payload, err := json.Marshal(event)
		if err != nil {
			fmt.Fprintf(os.Stdout, `{"timestamp":%q,"service":%q,"level":"error","message":"failed to marshal request log"}`+"\n", time.Now().UTC().Format(time.RFC3339Nano), serviceName)
			return
		}
		fmt.Fprintln(os.Stdout, string(payload))
	}
}

// Middleware applies profile behavior to simulation endpoints.
func (r *Runtime) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !r.cfg.enabled || c.Request.URL.Path != "/api/v1/sim/work" {
			c.Next()
			return
		}

		count := r.requests.Add(1)
		r.ensureMemoryPressure()
		r.burnCPU()

		if r.cfg.latencyMs > 0 {
			time.Sleep(time.Duration(r.cfg.latencyMs) * time.Millisecond)
		}

		if r.shouldTrigger(r.cfg.timeoutEvery, count) {
			c.Set(contextErrorType, "timeout")
			c.Set(contextMessage, "deadline exceeded while waiting for downstream dependency")
			c.AbortWithStatusJSON(http.StatusGatewayTimeout, gin.H{
				"error":   "simulated_timeout",
				"message": "deadline exceeded",
				"profile": r.cfg.profile,
			})
			return
		}

		if r.shouldTrigger(r.cfg.dependencyEvery, count) {
			c.Set(contextErrorType, "dependency_error")
			c.Set(contextMessage, "upstream unavailable: connection refused")
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"error":   "simulated_dependency_error",
				"message": "upstream unavailable: connection refused",
				"profile": r.cfg.profile,
			})
			return
		}

		if r.shouldTrigger(r.cfg.errorEvery, count) {
			c.Set(contextErrorType, "server_error")
			c.Set(contextMessage, "simulated server error")
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error":   "simulated_server_error",
				"message": "simulated server error",
				"profile": r.cfg.profile,
			})
			return
		}

		if r.cfg.crashAfterRequests > 0 && int(count) >= r.cfg.crashAfterRequests {
			c.Set(contextErrorType, "crash")
			c.Set(contextMessage, "panic: simulated crash loop")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "simulated_crash",
				"message": "panic: simulated crash loop",
				"profile": r.cfg.profile,
			})
			go func() {
				time.Sleep(50 * time.Millisecond)
				os.Exit(1)
			}()
			return
		}

		c.Next()
	}
}

// ReadyHandler is a readiness endpoint that can be made intentionally unstable.
func (r *Runtime) ReadyHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		count := r.readyChecks.Add(1)
		if r.cfg.enabled && r.shouldTrigger(r.cfg.probeFailureEvery, count) {
			c.Set(contextErrorType, "probe_failure")
			c.Set(contextMessage, "readiness probe failed")
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status":  "not_ready",
				"message": "readiness probe failed",
				"profile": r.cfg.profile,
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"status":  "ready",
			"profile": r.cfg.profile,
		})
	}
}

// InfoHandler exposes active simulation settings.
func (r *Runtime) InfoHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"enabled": r.cfg.enabled,
			"profile": r.cfg.profile,
			"service": r.cfg.serviceName,
		})
	}
}

// WorkHandler is the stable target for in-cluster load generation.
func (r *Runtime) WorkHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"profile": r.cfg.profile,
		})
	}
}

func (r *Runtime) shouldTrigger(every int, count uint64) bool {
	return every > 0 && count > 0 && count%uint64(every) == 0
}

func (r *Runtime) burnCPU() {
	if r.cfg.cpuBurnMs <= 0 {
		return
	}
	deadline := time.Now().Add(time.Duration(r.cfg.cpuBurnMs) * time.Millisecond)
	var x uint64
	for time.Now().Before(deadline) {
		x += uint64(time.Now().UnixNano())
	}
	runtime.KeepAlive(x)
}

func (r *Runtime) ensureMemoryPressure() {
	if r.cfg.memoryMB <= 0 {
		return
	}

	r.memoryMu.Lock()
	defer r.memoryMu.Unlock()

	currentMB := 0
	for _, block := range r.memoryBlocks {
		currentMB += len(block) / (1024 * 1024)
	}
	if currentMB >= r.cfg.memoryMB {
		return
	}

	remaining := r.cfg.memoryMB - currentMB
	block := make([]byte, remaining*1024*1024)
	for i := 0; i < len(block); i += 4096 {
		block[i] = byte(i)
	}
	r.memoryBlocks = append(r.memoryBlocks, block)
	runtime.KeepAlive(r.memoryBlocks)
}

func applyProfileDefaults(cfg *runtimeConfig) {
	if cfg.profile == "" {
		cfg.profile = "baseline"
	}

	switch cfg.profile {
	case "high-error-rate":
		setDefaultInt(&cfg.errorEvery, 5)
	case "high-latency":
		setDefaultInt(&cfg.latencyMs, 850)
	case "timeout-pressure":
		setDefaultInt(&cfg.latencyMs, 1100)
		setDefaultInt(&cfg.timeoutEvery, 3)
	case "dependency-instability":
		setDefaultInt(&cfg.dependencyEvery, 3)
	case "cpu-saturation":
		setDefaultInt(&cfg.cpuBurnMs, 250)
	case "memory-pressure":
		setDefaultInt(&cfg.memoryMB, 160)
	case "crash-loop":
		setDefaultInt(&cfg.crashAfterRequests, 20)
	case "probe-instability":
		setDefaultInt(&cfg.probeFailureEvery, 2)
	}
}

func normalizedProfile(profile string) string {
	profile = strings.TrimSpace(strings.ToLower(profile))
	if profile == "" {
		return "baseline"
	}
	return profile
}

func setDefaultInt(target *int, value int) {
	if *target == 0 {
		*target = value
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
