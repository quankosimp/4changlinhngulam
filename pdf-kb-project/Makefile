.PHONY: help start-all start stop status logs open setup deps

SHELL := /bin/bash
.ONESHELL:

COMPOSE ?= $(shell command -v docker-compose >/dev/null 2>&1 && echo docker-compose || echo "docker compose")

BACKEND_DIR := backend
FRONTEND_DIR := frontend

BACKEND_HOST ?= 0.0.0.0
BACKEND_PORT ?= 8000
FRONTEND_HOST ?= 0.0.0.0
FRONTEND_PORT ?= 3000

BACKEND_LOG := backend/backend-dev.log
FRONTEND_LOG := frontend/frontend-dev.log

help:
	@echo "Available targets:"
	@echo "  make setup   - Install backend/frontend dependencies"
	@echo "  make start-all- Start DB + backend + frontend in one terminal"
	@echo "  make stop    - Stop all dev servers and DB"
	@echo "  make status  - Show docker compose status"
	@echo "  make logs    - Tail backend/frontend logs"
	@echo "  make open    - Print local URLs"

setup:
	@if [ -f "$(BACKEND_DIR)/pyproject.toml" ]; then
		cd $(BACKEND_DIR) && python -m pip install -e .
	fi
	@if [ -f "$(FRONTEND_DIR)/package.json" ]; then
		cd $(FRONTEND_DIR) && npm install
	fi

start-all:
	@mkdir -p backend frontend
	@$(COMPOSE) up -d
	@cd $(BACKEND_DIR)
	@echo "Starting backend on http://$(BACKEND_HOST):$(BACKEND_PORT) ..."
	@nohup python -m uvicorn app.main:app --reload --host $(BACKEND_HOST) --port $(BACKEND_PORT) > ../$(BACKEND_LOG) 2>&1 &
	@BACKEND_PID=$$!
	@cd ../$(FRONTEND_DIR)
	@echo "Starting frontend on http://$(FRONTEND_HOST):$(FRONTEND_PORT) ..."
	@nohup npm run dev -- --hostname $(FRONTEND_HOST) --port $(FRONTEND_PORT) > ../$(FRONTEND_LOG) 2>&1 &
	@FRONTEND_PID=$$!
	@trap "kill $$BACKEND_PID $$FRONTEND_PID || true; $(COMPOSE) down; exit" INT TERM
	@echo "Backend PID: $$BACKEND_PID"
	@echo "Frontend PID: $$FRONTEND_PID"
	@echo "Logs:"
	@echo "  tail -f ../$(BACKEND_LOG)"
	@echo "  tail -f ../$(FRONTEND_LOG)"
	@echo "URLs:"
	@echo "  Frontend: http://localhost:$(FRONTEND_PORT)"
	@echo "  API:      http://localhost:$(BACKEND_PORT)"
	@wait

start: start-all

stop:
	@pkill -f "uvicorn app.main:app" || true
	@pkill -f "npm run dev" || true
	@$(COMPOSE) down

status:
	@$(COMPOSE) ps

logs:
	@tail -f $(BACKEND_LOG) $(FRONTEND_LOG)

open:
	@echo "Open:"
	@echo "  Frontend: http://localhost:$(FRONTEND_PORT)"
	@echo "  API:      http://localhost:$(BACKEND_PORT)"
	@echo "  Health:   http://localhost:$(BACKEND_PORT)/docs"
