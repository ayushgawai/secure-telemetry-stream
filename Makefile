.PHONY: test bench run lag
test:
	cd pipeline && mvn test
	cd api && go test ./...
bench:
	./scripts/bench.sh
run:
	docker compose up --build
lag:
	docker compose exec kafka kafka-consumer-groups --bootstrap-server kafka:9092 --describe --group sts-flink || true
