#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <pwd.h>
#include <gnome-keyring.h>

#define PASSWORD_LENGTH 4096
#define KEYADD_NAME "keyadd"
#define SOCKET_PATH "/tmp"
#define CONFIG_FILE "/etc/keyadd.conf"

int sock_listen = -1;
const char *sock_filename = NULL;
const char const *characters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKHLMNOPQRSTUVWXYZ";
char password[PASSWORD_LENGTH];

const char *status = "not registered";

const char const *environment_variable[] = {
	"DBUS_SESSION_BUS_ADDRESS",
	/*"GNOME_KEYRING_CONTROL",
	"GNOME_KEYRING_PID",*/
};

typedef struct Command {
	const char *command;
	void (*func)(const char *, int sock);
} Command;

static void command_set(const char *string, int sock) {
	char *name, *value;
	
	if(!(name = strdup(string)))
		return;
	
	if(!(value = strchr(name, '=')))
		return;
	
	*value++ = 0;
	setenv(name, value, 1);
	
	free(name);
}

static void command_password(const char *string, int sock) {
	snprintf(password, PASSWORD_LENGTH, "%s", string);
}

static void command_printenv(const char *string, int sock) {
	extern char **environ;
	char **env;
	env = environ;
	while(*env) {
		send(sock, *env, strlen(*env), 0);
		send(sock, "\n", 1, 0);
		env++;
	}
}

static void command_forget(const char *string, int sock) {
	memset(password, 0, PASSWORD_LENGTH);
}

static void command_register(const char *string, int sock) {
	FILE *conffile;
	struct passwd *pwd;
	GnomeKeyringResult result;
	guint32 item_id;
	
	pwd=getpwuid(getuid());
	
	if(!(conffile = fopen(CONFIG_FILE, "r")))
		return;
	
	status = "registered";
	
	while(!feof(conffile)) {
		char *line = NULL;
		char *protocol, *server;
		
		fscanf(conffile, "%m[^\n]", &line);
		getc(conffile);
		if(!line)
			continue;
		
		if(*line == '#' || !*line) {
			free(line);
			continue;
		}
		
		protocol = line;
		server = strchr(line, ' ');
		*server = 0;
		server++;
		
		result = gnome_keyring_set_network_password_sync(
			NULL,
			pwd->pw_name,
			NULL,
			server,
			NULL,
			protocol,
			"password",
			0,
			password,
			&item_id
		);
		
		if(result != GNOME_KEYRING_RESULT_OK)
			status = gnome_keyring_result_to_message(result);
		
		free(line);
	}
	
	fclose(conffile);
}

static void command_status(const char *string, int sock) {
	send(sock, status, strlen(status), 0);
	send(sock, "\n", 1, 0);
}

static void command_exit(const char *string, int sock) {
	close(sock);
	exit(0);
}

Command command[] = {
	{"set ", command_set},
	{"password ", command_password},
	{"printenv", command_printenv},
	{"forget", command_forget},
	{"register", command_register},
	{"status", command_status},
	{"exit", command_exit},
};

static void cleanup(void) {
	if(sock_listen >= 0)
		close(sock_listen);
	if(sock_filename)
		unlink(sock_filename);
	
	memset(password, 0, PASSWORD_LENGTH);
}

static void usage(void) {
	fprintf(stderr, "Usage: keyadd-daemon <--first-stage | --second-stage>\n");
}

static void do_command(const char *string, int sock) {
	int i;
	size_t len;
	
	for(i = 0; i < sizeof(command)/sizeof(Command); i++) {
		len = strlen(command[i].command);
		if(!strncmp(command[i].command, string, len))
			command[i].func(string + len, sock);
	}
}

static void listen_socket(const char *filename) {
	//TODO add error checking
	struct sockaddr_un local, remote;
	
	sock_filename = filename;
	sock_listen = socket(AF_UNIX, SOCK_STREAM, 0);
	local.sun_family = AF_UNIX;
	sprintf(local.sun_path, "%s", filename);
	unlink(local.sun_path);
	bind(sock_listen, (struct sockaddr *) &local, strlen(local.sun_path) + sizeof(local.sun_family));
	listen(sock_listen, 3);
	
	for(;;) {
		int sock;
		socklen_t socklen = sizeof(struct sockaddr_un);
		char buffer[257];
		char *buf = buffer;
		size_t bufsize = 256;
		
		buffer[256] = 0;
		
		sock = accept(sock_listen, (struct sockaddr *) &remote, &socklen);
		
		while(sock >= 0) {
			if(recv(sock, buf, 1, 0) <= 0) {
				close(sock);
				sock = -1;
				break;
			}
			
			if(*buf == '\n') {
				*buf = 0;
				do_command(buffer, sock);
				buf = buffer;
				bufsize = 256;
			} else if(bufsize) {
				buf++;
				bufsize--;
			}
		}
	}
}

static char *random_string(size_t len) {
	unsigned int i;
	size_t chars_len;
	char *string = malloc(len + 1);
	
	chars_len = strlen(characters);
	string[len] = 0;
	for(i = 0; i < len; i++)
		string[i] = characters[rand() % chars_len];
	
	return string;
}

static char *create_socket_filename() {
	char *filename = malloc(32);
	char *randstr = random_string(8);
	sprintf(filename, "%s/%s-%s", SOCKET_PATH, KEYADD_NAME, randstr);
	free(randstr);
	return filename;
}

static void first_stage(const char *filename) {
	pid_t pid;
	
	pid = fork();
	switch(pid) {
		case 0:
			/*Daemonize*/
			if(setsid() < 0) {
				fprintf(stderr, "%s: Failed to setsid daemon process\n", KEYADD_NAME);
				return;
			}
			chdir("/");
			freopen("/dev/null", "r", stdin);
			freopen("/dev/null", "w", stdout);
			freopen("/dev/null", "w", stderr);
			umask(S_IRWXG | S_IRWXO);
			atexit(cleanup);
			
			listen_socket(filename);
			break;
		case -1:
			fprintf(stderr, "%s: Failed to fork new process\n", KEYADD_NAME);
			return;
		default:
			break;
	}
}

static void second_stage(const char *filename) {
	struct sockaddr_un addr;
	int i, sock;
	size_t len;
	char *value, *message;
	
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	addr.sun_family = AF_UNIX;
	sprintf(addr.sun_path, "%s", filename);
	
	if(connect(sock, (struct sockaddr *) &addr, strlen(addr.sun_path) + sizeof(addr.sun_family)) < 0) {
		fprintf(stderr, "%s: Failed to connect to running daemon\n", KEYADD_NAME);
		return;
	}
	
	for(i = 0; i < sizeof(environment_variable)/sizeof(char *); i++) {
		if(!(value = getenv(environment_variable[i]))) {
			fprintf(stderr, "%s: Missing variable %s from environment\n", KEYADD_NAME, environment_variable[i]);
			return;
		}
		
		len = snprintf(NULL, 0, "set %s=%s\n", environment_variable[i], value);
		message = malloc(len + 1);
		sprintf(message, "set %s=%s\n", environment_variable[i], value);
		
		send(sock, message, len, 0);
		free(message);
	}
	
	message = "register\n";
	send(sock, message, strlen(message), 0);
	message = "forget\n";
	send(sock, message, strlen(message), 0);
	
	close(sock);
}

int main(int argc, char **argv) {
	if(argc != 2) {
		usage();
		return 1;
	}
	
	srand(time(NULL));
	
	if(!strcmp(argv[1], "--first-stage")) {
		char *filename = create_socket_filename();
		first_stage(filename);
		printf("KEYADD_SOCK=%s\n", filename);
		free(filename);
	} else if(!strcmp(argv[1], "--second-stage")) {
		char *filename;
		if(!(filename = getenv("KEYADD_SOCK"))) {
			fprintf(stderr, "%s: environment variable KEYADD_SOCK missing\n", KEYADD_NAME);
			return 1;
		}
		second_stage(filename);
	} else {
		usage();
		return 1;
	}
	
	return 0;
}
