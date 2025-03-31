# Kubernetes Deployment

This directory contains Kubernetes manifests for deploying the Go API application.

## Prerequisites

- Kubernetes cluster
- kubectl configured to use your cluster
- Docker image built and available in your cluster's registry

## Deployment Steps

1. Build and tag the Docker image:
```bash
docker build -t go-api:latest .
```

2. If using a remote registry, tag and push the image:
```bash
docker tag go-api:latest your-registry/go-api:latest
docker push your-registry/go-api:latest
```

3. Apply the Kubernetes manifests:
```bash
kubectl apply -f configmap.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
```

4. Verify the deployment:
```bash
kubectl get pods
kubectl get services
```

## Configuration

The deployment includes:
- 2 replicas for high availability
- Resource limits and requests
- Health checks (liveness and readiness probes)
- LoadBalancer service type for external access
- ConfigMap for environment variables

## Monitoring

To check the status of your deployment:
```bash
kubectl get deployments
kubectl describe deployment go-api
```

To view logs:
```bash
kubectl logs -l app=go-api
``` 