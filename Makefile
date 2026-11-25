# idp-mcp-bridge build and test entry points.
PG_IMAGE ?= ghcr.io/idp-xyz/mirror:public.ecr.aws__docker__library__postgres__17-alpine
PG_NAME  ?= idp-mcp-bridge-test-pg

.PHONY: build vet test image test-integration pg-up pg-down

build:
	go build -o bin/ ./cmd/...

vet:
	gofmt -l . | (! grep .) && go vet ./...

# ./... includes tests/deploy: the Kubernetes manifests against the code (the egress policy against internal/addr).
# The tests that need a database (the grants store, the OAuth flows over PostgreSQL, the refresh across replicas) are skipped
# here: make test-integration runs them.
test: vet
	go test -race ./...

# Starts a throwaway PostgreSQL on a random loopback port, runs every test of the repository against it (the flows of
# internal/app and the store of internal/grants run over PostgreSQL as well as over memory) and removes it again. PG_NAME names
# the container: pick another to run two at once.
test-integration: pg-up
	@PORT=$$(docker port $(PG_NAME) 5432/tcp | head -1 | sed 's/.*://'); \
	IDP_TEST_PG_OWNER_URL="postgres://postgres:test@127.0.0.1:$$PORT/postgres?sslmode=disable" \
	go test -count=1 -race ./... ; status=$$?; \
	$(MAKE) --no-print-directory pg-down; exit $$status

pg-up:
	@docker rm -f $(PG_NAME) >/dev/null 2>&1 || true
	@bash deploy/pull-image.sh $(PG_IMAGE)
	@docker run -d --name $(PG_NAME) -e POSTGRES_PASSWORD=test -p 127.0.0.1::5432 $(PG_IMAGE) >/dev/null
	@for i in $$(seq 1 60); do docker exec $(PG_NAME) pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && break; sleep 0.5; done

pg-down:
	@docker rm -f $(PG_NAME) >/dev/null 2>&1 || true

# the image, built offline (a static binary on the host, then docker build --network none)
image:
	bash deploy/build.sh
