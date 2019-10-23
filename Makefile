.PHONY: gosch
gosch:
	go build 
netbsd:
	GOOS=netbsd GOARCH=amd64 go build -o gosch.nb64
test:
	go test ./... -v -count 1
