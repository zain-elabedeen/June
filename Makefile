KUBE_NAMESPACE ?= june-sim
RELEASE ?= june-api
API_IMAGE ?= june-api
API_TAG ?= dev
MIGRATIONS_IMAGE ?= june-api-migrations
MIGRATIONS_TAG ?= dev
SCENARIO ?= baseline
SCENARIO_FILE := ./helm/june-api/scenarios/$(SCENARIO).yaml
LOADGEN_DURATION ?= 120
LOADGEN_WORKERS ?= 5
LOADGEN_DELAY ?= 0
LOADGEN_TIMEOUT ?= 2
LOADGEN_WAIT_TIMEOUT ?= 600s

.PHONY: minikube-build deploy-local local-up scenario loadgen wait-local wait-loadgen local-down port-forward status scenarios

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

scenario: minikube-build
	test -f $(SCENARIO_FILE)
	helm upgrade --install $(RELEASE) ./helm/june-api \
		--namespace $(KUBE_NAMESPACE) \
		--create-namespace \
		-f ./helm/june-api/values-local.yaml \
		-f $(SCENARIO_FILE) \
		--set image.repository=$(API_IMAGE) \
		--set image.tag=$(API_TAG) \
		--set migrations.image.repository=$(MIGRATIONS_IMAGE) \
		--set migrations.image.tag=$(MIGRATIONS_TAG) \
		--set loadgen.enabled=false
	$(MAKE) wait-local
	kubectl -n $(KUBE_NAMESPACE) delete job -l app.kubernetes.io/component=loadgen --ignore-not-found
	helm upgrade $(RELEASE) ./helm/june-api \
		--namespace $(KUBE_NAMESPACE) \
		-f ./helm/june-api/values-local.yaml \
		-f $(SCENARIO_FILE) \
		--set image.repository=$(API_IMAGE) \
		--set image.tag=$(API_TAG) \
		--set migrations.image.repository=$(MIGRATIONS_IMAGE) \
		--set migrations.image.tag=$(MIGRATIONS_TAG) \
		--set loadgen.enabled=true
	$(MAKE) wait-loadgen

loadgen:
	kubectl -n $(KUBE_NAMESPACE) delete job -l app.kubernetes.io/component=loadgen --ignore-not-found
	helm upgrade $(RELEASE) ./helm/june-api \
		--namespace $(KUBE_NAMESPACE) \
		--reuse-values \
		--set loadgen.enabled=true \
		--set loadgen.durationSeconds=$(LOADGEN_DURATION) \
		--set loadgen.workers=$(LOADGEN_WORKERS) \
		--set loadgen.delaySeconds=$(LOADGEN_DELAY) \
		--set loadgen.timeoutSeconds=$(LOADGEN_TIMEOUT)
	$(MAKE) wait-loadgen

local-up: deploy-local wait-local

wait-local:
	kubectl -n $(KUBE_NAMESPACE) rollout status deployment/$(RELEASE)-postgresql --timeout=180s
	kubectl -n $(KUBE_NAMESPACE) wait --for=condition=complete job -l app.kubernetes.io/component=migrations --timeout=180s
	kubectl -n $(KUBE_NAMESPACE) rollout status deployment/$(RELEASE) --timeout=180s

wait-loadgen:
	kubectl -n $(KUBE_NAMESPACE) wait --for=condition=complete job -l app.kubernetes.io/component=loadgen --timeout=$(LOADGEN_WAIT_TIMEOUT)

local-down:
	helm uninstall $(RELEASE) --namespace $(KUBE_NAMESPACE) --ignore-not-found

port-forward:
	kubectl -n $(KUBE_NAMESPACE) port-forward svc/$(RELEASE) 9000:80

status:
	kubectl -n $(KUBE_NAMESPACE) get pods,deploy,svc,jobs,pvc

scenarios:
	ls ./helm/june-api/scenarios/*.yaml | xargs -n1 basename | sed 's/.yaml//'
