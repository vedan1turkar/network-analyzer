# DONET Network Analyzer - Build System
.PHONY: all install test clean deb rpm docker help

all: help

help:
	@echo "DONET Network Analyzer - Build & Install"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  install       Install locally (pip install -e .)"
	@echo "  test          Run unit tests"
	@echo "  clean         Clean build artifacts"
	@echo "  deb           Build Debian/Ubuntu .deb package"
	@echo "  rpm           Build RPM package (requires rpm-build)"
	@echo "  docker        Build Docker image"
	@echo "  docker-run    Build and run Docker container"
	@echo "  quick-install Run quick install script (bash)"
	@echo "  help          Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make install          # Install for current user"
	@echo "  make test             # Run tests"
	@echo "  make deb              # Create .deb package"
	@echo "  make docker           # Build Docker image"
	@echo ""

install:
	@echo "Installing DONET..."
	pip3 install --user -e .
	@echo ""
	@echo "✓ Installed! Run 'donet --help' to get started."

test:
	@echo "Running tests..."
	pytest tests/ -v

clean:
	@echo "Cleaning..."
	rm -rf debian-build donet_*.deb donet-*.rpm rpm-build
	rm -rf __pycache__ *.pyc .pytest_cache .coverage htmlcov
	rm -rf build/ dist/ *.egg-info
	@echo "✓ Clean complete"

deb:
	@echo "Building Debian package..."
	bash build-deb.sh

rpm:
	@echo "Building RPM package..."
	bash build-rpm.sh

docker:
	@echo "Building Docker image..."
	docker build -t donet/network-analyzer:latest .
	@echo ""
	@echo "✓ Docker image built: donet/network-analyzer:latest"
	@echo "Run with: docker run --rm --network host --privileged donet/network-analyzer:latest --help"

docker-run:
	@echo "Building and running Docker container..."
	docker-compose up

quick-install:
	@echo "Running quick install script..."
	bash install.sh
