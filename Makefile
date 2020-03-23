LD_FLAGS='-s -w'
BUILD_DIR=./build
INSTDIR=/usr/lib/mongooseim/bin/
BINARY=ldap_auth

clean: 
	rm -rf $(BUILD_DIR)
build: 
	mkdir $(BUILD_DIR)
	go get -u gopkg.in/ldap.v3
	go build -ldflags=$(LD_FLAGS) -o $(BUILD_DIR)/$(BINARY)
install: build
	test -d $(INSTDIR) || mkdir -p $(INSTDIR)
	install -d $(INSTDIR)
	install -m 755 $(BUILD_DIR)/$(BINARY) $(INSTDIR)

.DEFAULT_GOAL = build
