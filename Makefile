.PHONY: gosch
gosch:
	go build 
netbsd:
	GOOS=netbsd GOARCH=amd64 go build -o gosch.nb64
test:
	go test -race ./... -v -count 1 -test.timeout 20s
