BINARY_NAME=infra-observer
INSTALL_DIR=/usr/local/bin

.PHONY: all build install uninstall clean test

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	go build -ldflags="-s -w" -o $(BINARY_NAME) ./cmd/infra-observer

install: build
	@echo "Installing $(BINARY_NAME) to $(INSTALL_DIR)..."
	install -m 755 $(BINARY_NAME) $(INSTALL_DIR)
	@echo "Installation complete. You can now run 'infra-observer' from anywhere."

uninstall:
	@echo "Removing $(BINARY_NAME) from $(INSTALL_DIR)..."
	rm -f $(INSTALL_DIR)/$(BINARY_NAME)

clean:
	@echo "Cleaning up..."
	go clean
	rm -f $(BINARY_NAME)

test:
	go test -v ./...
