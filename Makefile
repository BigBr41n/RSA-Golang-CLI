# Build the Go CLI app
build:
	go build -o myapp main.go

# Run the Go CLI app to generate RSA keys
generate:
	./myapp generate
