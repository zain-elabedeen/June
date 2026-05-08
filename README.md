# June LoadGen 

June is a Load generator used for Kubernetes deployment experiments.

## Project Structure

```
.
├── main.go           # Main application entry point
├── handlers/         # Request handlers
├── middleware/       # Custom middleware
├── models/          # Data models
├── routes/          # Route definitions
└── config/          # Configuration files
```

## Setup

1. Make sure you have Go installed (version 1.21 or higher)
2. Install dependencies:
   ```bash
   go mod tidy
   ```
3. Run the application:
   ```bash
   go run main.go
   ```

The API will be available at `http://localhost:8080`

## Local Kubernetes on Minikube

The Helm chart supports an opt-in local stack with the API, PostgreSQL, and database migrations.

One-command local deploy:

```bash
minikube start
make local-up
make port-forward
```

Then open `http://localhost:9000/health`.

Useful commands:

```bash
make status
make local-down
```

To generate test data, run one of the deterministic scenarios:

```bash
make scenarios
make scenario SCENARIO=high-error-rate
```

To generate more traffic for the currently deployed scenario:

```bash
make loadgen LOADGEN_DURATION=300
```

Scenario details live in `docs/archagent-scenarios.md`

If you have Skaffold installed, you can also run:

```bash
skaffold dev
```

Local settings live in `helm/june-api/values-local.yaml`. Production defaults keep local PostgreSQL and migrations disabled, so your GCP database setup can continue to use external values/secrets.

## Simulator

June includes a deterministic simulator for generating Kubernetes metrics and pod logs.

The simulator is controlled by environment variables rendered from Helm values:

```text
JUNE_SIM_ENABLED=true
JUNE_SIM_PROFILE=high-error-rate
```

The main simulation target is:

```text
GET /api/v1/sim/work
```

Every request emits a JSON log line to stdout

```json
{
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

## Scenarios

List available scenarios:

```bash
make scenarios
```

Run a scenario:

```bash
make scenario SCENARIO=timeout-pressure
```

This builds the local images, deploys the selected Helm scenario, waits for API/PostgreSQL/migrations, then runs one loadgen Job.

Current scenarios include:

```text
baseline
high-error-rate
high-latency
timeout-pressure
dependency-instability
cpu-saturation
memory-pressure
crash-loop
probe-instability
single-instance
coupling-risk
```

Detailed expected signals and smells are documented in `docs/archagent-scenarios.md`.

## Load Generation

`make scenario` runs loadgen once after deploying the scenario. To rerun traffic against the currently deployed scenario without changing API pods:

```bash
make loadgen
```

By default, this sends traffic for 120 seconds using 5 parallel workers:

```text
LOADGEN_DURATION=120
LOADGEN_WORKERS=5
LOADGEN_DELAY=0
LOADGEN_TIMEOUT=2
```

Examples:

```bash
make loadgen LOADGEN_DURATION=300
make loadgen LOADGEN_DURATION=300 LOADGEN_WORKERS=10
make loadgen LOADGEN_DURATION=300 LOADGEN_WORKERS=10 LOADGEN_DELAY=1
```

The loadgen Job targets:

```text
http://june-api:80/api/v1/sim/work
```

Failed HTTP responses do not fail the Job. That is intentional because scenarios such as `high-error-rate`, `timeout-pressure`, and `dependency-instability` are supposed to produce 500/503/504 responses.

## API Endpoints

- `GET /`: Welcome message
- `GET /health`: liveness check
- `GET /ready`: readiness check, simulation-aware
- `GET /api/v1/sim`: active simulator profile
- `GET /api/v1/sim/work`: simulator/loadgen target
