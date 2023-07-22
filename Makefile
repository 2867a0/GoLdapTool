LDFLAGS = -ldflags "-s -w -extldflags '-static'"

.PHONY: all
all: clean win macos macos-arm64
	
.PHONY: win
win: 
	GOOS=windows GOARCH=amd64 go build -tags release $(LDFLAGS) -o bin/GoLdapTools-win-amd64.exe goLdapTools

.PHONY: macos
macos:
	GOOS=darwin GOARCH=amd64 go build -tags release $(LDFLAGS) -o bin/GoLdapTools-macos-amd64 goLdapTools

.PHONY: macos-arm64
macos-arm64:
	GOOS=darwin GOARCH=arm64 go build -tags release $(LDFLAGS) -o bin/GoLdapTools-macos-arm64 goLdapTools


clean:
	rm -f bin/*
