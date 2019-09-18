SHELL := /bin/bash
GITCOMMIT=$(shell git describe --tags HEAD)$(shell [[ $$(git status --porcelain) = "" ]] || echo -dirty)
LDFLAGS="-X main.gitCommit=$(GITCOMMIT)"

AZURE_IMAGE ?= quay.io/openshift-on-azure/azure:$(GITCOMMIT)
AZURE_IMAGE_ACR ?= osarpint.azurecr.io/openshift-on-azure/azure:$(GITCOMMIT)
LATEST_PLUGIN_VERSION=v$(shell ls -d pkg/sync/v* | sed -e 's/.*v//' | tail -1)

.PHONY: all artifacts azure-image azure-push clean create delete e2e generate monitoring monitoring-run monitoring-stop secrets sync-run test testinsights unit upgrade verify vmimage

all: azure

secrets:
	@rm -rf secrets
	@mkdir secrets
	@oc extract -n azure secret/cluster-secrets-azure --to=secrets >/dev/null

private-secrets:
	@echo "These secrets are sensitive, please do not keep them on your workstation. Execute make private-secrets-clean after you done" 
	@rm -rf private-secrets
	@mkdir private-secrets
	@oc extract -n azure-private secret/cluster-secrets-azure --to=private-secrets >/dev/null

private-secrets-clean:
	@rm -rf private-secrets	

clean:
	rm -f coverage.out azure releasenotes testinsights

generate:
	@[[ -e /var/run/secrets/kubernetes.io ]] || go generate ./...

test: unit e2e

create:
	./hack/create.sh ${RESOURCEGROUP}

delete:
	./hack/delete.sh ${RESOURCEGROUP}

upgrade:
	./hack/upgrade.sh ${RESOURCEGROUP}

artifacts:
	./hack/artifacts.sh

azure-image: azure
	./hack/image-build.sh images/azure/Dockerfile $(AZURE_IMAGE)

azure-push: azure-image
	docker push $(AZURE_IMAGE)
	if [ -a private-secrets/acr-docker-pull-push-secret ] ; \
	then \
		docker tag $(AZURE_IMAGE) $(AZURE_IMAGE_ACR) ; \
		cp private-secrets/acr-docker-pull-push-secret private-secrets/config.json ; \
		docker --config private-secrets/ push $(AZURE_IMAGE_ACR) ; \
	fi;

azure: generate
	go build -ldflags ${LDFLAGS} ./cmd/$@

sync-run: generate
	go run -ldflags ${LDFLAGS} ./cmd/azure sync --run-once --loglevel Debug

monitoring:
	go build -ldflags ${LDFLAGS} ./cmd/$@

monitoring-run: monitoring
	./hack/monitoring.sh

monitoring-stop:
	./hack/monitoring.sh clean

releasenotes:
	go build -tags releasenotes ./cmd/$@

content:
	go test -timeout=300s -tags=content -run=TestContent ./pkg/sync/$(LATEST_PLUGIN_VERSION)
	go generate ./pkg/sync/$(LATEST_PLUGIN_VERSION)

verify:
	go test -c -tags=content -run=TestContent ./pkg/sync/$(LATEST_PLUGIN_VERSION) && rm $(LATEST_PLUGIN_VERSION).test
	./hack/verify/validate-generated.sh
	go vet ./...
	./hack/verify/validate-code-format.sh
	./hack/verify/validate-util.sh
	./hack/verify/validate-codecov.sh
	go run ./hack/validate-imports/validate-imports.go cmd hack pkg test
	./hack/verify/validate-sec.sh

testinsights:
	go build -ldflags ${LDFLAGS} ./cmd/$@

unit: generate testinsights
	go test ./... -coverprofile=coverage.out -covermode=atomic -json | ./testinsights

e2e:
	FOCUS="\[CustomerAdmin\]|\[EndUser\]" TIMEOUT=60m ./hack/e2e.sh

vmimage:
	./hack/vmimage.sh

vmimage-validate:
	./hack/vmimage-validate.sh
