.PHONY: start stop restart test iterate

start:
	./scripts/restart_api.sh

test:
	./scripts/healthcheck.sh

iterate:
	MAX_ITERS?=3 ./scripts/iterate_heva.sh

restart: start

