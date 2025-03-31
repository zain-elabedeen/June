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

## API Endpoints

- `GET /`: Welcome message 