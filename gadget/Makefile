CONTAINER_REPO ?= ghcr.io/alban/runc-vuln-detector
IMAGE_TAG ?= latest

CLANG_FORMAT ?= clang-format

.PHONY: build
build:
	IG_EXPERIMENTAL=true sudo -E \
		ig image build \
			-t $(CONTAINER_REPO):$(IMAGE_TAG) \
			--update-metadata .

.PHONY: run
run:
	IG_EXPERIMENTAL=true sudo -E \
		ig run $(CONTAINER_REPO):$(IMAGE_TAG) $$PARAMS

.PHONY: push
push:
	IG_EXPERIMENTAL=true sudo -E \
		ig image push $(CONTAINER_REPO):$(IMAGE_TAG)

push-artifacthub:
	oras push \
		$(CONTAINER_REPO):artifacthub.io \
		--config /dev/null:application/vnd.cncf.artifacthub.config.v1+yaml \
		artifacthub-repo.yml:application/vnd.cncf.artifacthub.repository-metadata.layer.v1.yaml

.PHONY: clang-format
clang-format:
	$(CLANG_FORMAT) -i program.bpf.c
