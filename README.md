# Go API Project

A skeleton project for a Go API using the Gin framework.

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

The Helm chart supports an opt-in local stack with the API, PostgreSQL, and the migration job.

One-command local deploy:

```bash
minikube start
make local-up
make port-forward
```

Then open `http://localhost:8080/health`.

Useful commands:

```bash
make status
make local-down
```

If you have Skaffold installed, you can also run:

```bash
skaffold dev
```

Local settings live in `helm/june-api/values-local.yaml`. Production defaults keep local PostgreSQL and migrations disabled, so your GCP database setup can continue to use external values/secrets.

## API Endpoints

- `GET /`: Welcome message
