CFLAGS	+= -Wall
LDFLAGS	+= 

all:
	@echo [ CC ] keyadd-test
	@$(CC) $(CFLAGS) -o keyadd-test keyadd-test.c $(shell pkg-config --cflags --libs gnome-keyring-1) $(LDFLAGS)
	@echo [ CC ] keyadd-daemon
	@$(CC) $(CFLAGS) -o keyadd-daemon keyadd-daemon.c $(shell pkg-config --cflags --libs gnome-keyring-1) $(LDFLAGS)
	@echo [ CC ] pam_keyadd.so
	@$(CC) $(CFLAGS) -fPIC -shared -o pam_keyadd.so pam_keyadd.c -shared -Wl,-soname,pam_keyadd.so -lpam $(LDFLAGS)

clean:
	@rm -f keyadd-test keyadd-daemon pam_keyadd.so

install:
	@install -d /etc/xdg/autostart
	@install -d /lib/security
	@install -d /usr/local/bin
	
	@echo [INST] pam_keyadd.so
	@install -t /lib/security -s pam_keyadd.so
	@echo [INST] keyadd-daemon
	@install -t /usr/local/bin -s keyadd-daemon
	@echo [INST] keyadd.desktop
	@install -m 644 -t /etc/xdg/autostart keyadd.desktop
