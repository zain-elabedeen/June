# Arch Agent Simulation Scenarios

June API can run deterministic local Kubernetes scenarios that generate Kubernetes metrics and JSON request logs for Arch Agent.

Use a dedicated namespace so Arch Agent can collect only this test system:

```bash
export ARCHAGENT_K8S_INCLUDE_NAMESPACES=june-sim
```

## Running A Scenario

```bash
minikube start
make scenario SCENARIO=high-error-rate
make status
```

The scenario command deploys the selected scenario and runs one load generation pass.

To rerun load generation against the already deployed scenario without changing the API pods:

```bash
make loadgen
```

`make loadgen` runs for a duration. The default is 120 seconds:

```bash
make loadgen LOADGEN_DURATION=300
```

Useful overrides:

```bash
make loadgen LOADGEN_DURATION=300 LOADGEN_WORKERS=10 LOADGEN_DELAY=1
```

This keeps sending requests for 300 seconds from 10 parallel workers, sleeping 1 second between requests in each worker.

Port-forward the API if you want to inspect it manually:

```bash
make port-forward
curl http://localhost:9000/health
curl http://localhost:9000/api/v1/sim
```

List available scenarios:

```bash
make scenarios
```

## Scenario Matrix

| Scenario | Generated behavior | Primary Arch Agent evidence |
| --- | --- | --- |
| `baseline` | Normal `/api/v1/sim/work` requests | Healthy request logs, service topology |
| `high-error-rate` | Every fifth simulation request returns HTTP 500 | `error_rate`, `status_5xx_rate`, `error_burst`, `high_error_rate` |
| `high-latency` | Simulation requests sleep around 850ms | `request_latency_p95_ms` log evidence |
`| `timeout-pressure` | Slow requests and every third request returns HTTP 504 with timeout text | `timeout_count`, `request_latency_p95_ms`, `timeout_pressure` |
| `dependency-instability` | Every third request returns HTTP 503 with connection refused text | `dependency_error_count`, `dependency_instability` |
| `cpu-saturation` | CPU burn under a low CPU limit while loadgen runs | `cpu_utilization`, `cpu_saturation` |
| `memory-pressure` | Retained heap allocation under a memory limit | `memory_utilization`, `memory_pressure` |
| `crash-loop` | The API exits after a small number of simulation requests | pod restarts, `restart_instability`, crash log evidence |
| `probe-instability` | `/ready` intermittently returns HTTP 503 | readiness failures, `probe_instability`, possible `replica_unavailability` |
| `single-instance` | API runs with one replica | `single_instance_risk` |
| `coupling-risk` | API is annotated as depending on DB plus four mock services | topology edges, `coupling_risk` |

## What Arch Agent Reads

The API emits JSON logs shaped for the existing Arch Agent log normalizer:

```json
{
  "timestamp": "2026-05-08T12:00:00Z",
  "service": "june-api",
  "level": "error",
  "method": "GET",
  "route": "/api/v1/sim/work",
  "status_code": 500,
  "latency_ms": 12.4,
  "error_type": "server_error",
  "message": "simulated server error"
}
```

The Helm chart also labels API, PostgreSQL, load generator, and mock dependency pods distinctly so Arch Agent can build a cleaner service graph from Kubernetes labels.
