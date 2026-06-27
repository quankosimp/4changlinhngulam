.PHONY: help setup dev dev-db start start-all stop status logs open test

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
	@echo "  make dev     - Start backend + frontend in one terminal"
	@echo "  make dev-db  - Start DB + backend + frontend"
	@echo "  make stop    - Stop dev servers and DB"
	@echo "  make logs    - Tail backend/frontend logs"
	@echo "  make test    - Run backend tests + frontend build"
	@echo "  make open    - Print local URLs"

setup:
	@if [ -f "$(BACKEND_DIR)/pyproject.toml" ]; then
		(cd $(BACKEND_DIR) && python -m pip install -e .[test])
	fi
	@if [ -f "$(FRONTEND_DIR)/package.json" ]; then
		(cd $(FRONTEND_DIR) && npm install)
	fi

dev:
	@set -e
	@mkdir -p backend frontend
	@if [ -f .env ]; then set -a; source .env; set +a; fi
	@if [ -f backend/.env ]; then set -a; source backend/.env; set +a; fi
	@if [ -z "$$OPENAI_API_KEY" ]; then echo "WARN: OPENAI_API_KEY is not set for backend."; fi
	@echo "Starting backend on http://$(BACKEND_HOST):$(BACKEND_PORT) ..."
	@(cd $(BACKEND_DIR) && python -m uvicorn app.main:app --reload --host $(BACKEND_HOST) --port $(BACKEND_PORT)) > $(BACKEND_LOG) 2>&1 &
	@BACKEND_PID=$$!
	@echo "Starting frontend on http://$(FRONTEND_HOST):$(FRONTEND_PORT) ..."
	@(cd $(FRONTEND_DIR) && npm run dev -- --hostname $(FRONTEND_HOST) --port $(FRONTEND_PORT)) > $(FRONTEND_LOG) 2>&1 &
	@FRONTEND_PID=$$!
	@trap 'kill $$BACKEND_PID $$FRONTEND_PID 2>/dev/null || true; exit' INT TERM EXIT
	@echo "Backend PID:  $$BACKEND_PID"
	@echo "Frontend PID: $$FRONTEND_PID"
	@echo "Logs: tail -f $(BACKEND_LOG) $(FRONTEND_LOG)"
	@echo "Frontend: http://localhost:$(FRONTEND_PORT)"
	@echo "API:      http://localhost:$(BACKEND_PORT)"
	@wait $$BACKEND_PID $$FRONTEND_PID

dev-db:
	@$(COMPOSE) up -d
	@$(MAKE) dev

start: dev
start-all: dev-db

stop:
	@pkill -f "uvicorn app.main:app" || true
	@pkill -f "next dev" || true
	@pkill -f "npm run dev" || true
	@$(COMPOSE) down || true

status:
	@$(COMPOSE) ps

logs:
	@tail -f $(BACKEND_LOG) $(FRONTEND_LOG)

test:
	@(cd $(BACKEND_DIR) && python -m pytest -q)
	@(cd $(FRONTEND_DIR) && npm run build)

open:
	@echo "Open:"
	@echo "  Frontend: http://localhost:$(FRONTEND_PORT)"
	@echo "  API:      http://localhost:$(BACKEND_PORT)"
	@echo "  Health:   http://localhost:$(BACKEND_PORT)/docs"
