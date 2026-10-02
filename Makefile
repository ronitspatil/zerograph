.PHONY: init up down test backend-test frontend-test
init:
	python3 deploy/init_env.py
up:
	docker compose up --build -d
down:
	docker compose down
test: backend-test frontend-test
backend-test:
	cd backend && .venv/bin/pytest
frontend-test:
	cd frontend && npm run typecheck && npm test
