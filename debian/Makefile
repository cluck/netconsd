# Makefile

DEBPKGNAME := $(shell awk -F': ' '/^Package: / {print $$2}' src/DEBIAN/control)
DEBPKGVERS := $(shell awk -F': ' '/^Version: / {print $$2}' src/DEBIAN/control)
	
all:
	install -m 0755 ../netconsd ./src/usr/local/bin/netconsd
	install -m 0644 ../modules/printer.so ./src/usr/local/lib/printer.so
	install -m 0644 ../modules/logger-simple.so ./src/usr/local/lib/logger-simple.so
	install -m 0644 ../modules/logger-advanced.so ./src/usr/local/lib/logger-advanced.so
	install -m 0644 ../modules/tsvlogger.so ./src/usr/local/lib/tsvlogger.so
	install -m 0644 ../modules/jsonlogger.so ./src/usr/local/lib/jsonlogger.so
	dpkg-deb --root-owner-group --build src "$(DEBPKGNAME)_$(DEBPKGVERS)_all.deb"

install:
	dpkg -i "$(DEBPKGNAME)_$(DEBPKGVERS)_all.deb"

clean:
	rm -f ./src/usr/local/bin/netconsd
	rm -f ./src/usr/local/lib/*.so

