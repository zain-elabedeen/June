KUBE_NAMESPACE ?= default
RELEASE ?= june-api
API_IMAGE ?= june-api
API_TAG ?= dev
MIGRATIONS_IMAGE ?= june-api-migrations
MIGRATIONS_TAG ?= dev

.PHONY: minikube-build deploy-local local-up wait-local local-down port-forward status

minikube-build:
	eval $$(minikube docker-env) && docker build -t $(API_IMAGE):$(API_TAG) .
	eval $$(minikube docker-env) && docker build -t $(MIGRATIONS_IMAGE):$(MIGRATIONS_TAG) -f Dockerfile.migrations .

deploy-local: minikube-build
	helm upgrade --install $(RELEASE) ./helm/june-api \
		--namespace $(KUBE_NAMESPACE) \
		--create-namespace \
		-f ./helm/june-api/values-local.yaml \
		--set image.repository=$(API_IMAGE) \
		--set image.tag=$(API_TAG) \
		--set migrations.image.repository=$(MIGRATIONS_IMAGE) \
		--set migrations.image.tag=$(MIGRATIONS_TAG)

local-up: deploy-local wait-local

wait-local:
	kubectl -n $(KUBE_NAMESPACE) rollout status deployment/$(RELEASE)-postgresql --timeout=180s
	kubectl -n $(KUBE_NAMESPACE) wait --for=condition=complete job -l app.kubernetes.io/component=migrations --timeout=180s
	kubectl -n $(KUBE_NAMESPACE) rollout status deployment/$(RELEASE) --timeout=180s

local-down:
	helm uninstall $(RELEASE) --namespace $(KUBE_NAMESPACE) --ignore-not-found

port-forward:
	kubectl -n $(KUBE_NAMESPACE) port-forward svc/$(RELEASE) 9000:80

status:
	kubectl -n $(KUBE_NAMESPACE) get pods,svc,jobs,pvc
