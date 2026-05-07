APP=server

.PHONY: test integration-test compose-up compose-down seed-dev

test:
	go test ./...

integration-test:
	go test ./tests/integration/...

compose-up:
	docker compose up -d --build

compose-down:
	docker compose down

seed-dev:
	sh scripts/seed-dev.sh
