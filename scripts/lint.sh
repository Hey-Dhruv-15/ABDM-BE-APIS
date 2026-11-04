#!/bin/bash
set -e

# Run linting and formatting checks

echo "Running Ruff for linting and formatting..."
ruff check app tests
ruff format --check app tests

echo "Running Mypy for type checking..."
mypy app

echo "All checks passed!"
