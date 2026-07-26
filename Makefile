.PHONY: install test lint fmt integration clean

install:
	pip install -e ".[dev]"

test:
	pytest -m "not integration" --cov=dhcpig --cov-report=term-missing

lint:
	ruff check src tests
	ruff format --check src tests
	mypy src/dhcpig/core

fmt:
	ruff check --fix src tests
	ruff format src tests

# Privileged: sets up a veth pair + fake DHCP server. Run as root on Linux.
integration:
	sudo $${VIRTUAL_ENV:-.venv}/bin/pytest -m integration -v

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache .coverage *.egg-info
	find . -name __pycache__ -type d -exec rm -rf {} +
