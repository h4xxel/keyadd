#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

char password[4096];
char *socket_filename;

static void socket_send_string(const char *sock_filename, const char *string) {
	struct sockaddr_un addr;
	int sock;
	
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	addr.sun_family = AF_UNIX;
	sprintf(addr.sun_path, "%s", sock_filename);
	
	if(connect(sock, (struct sockaddr *) &addr, strlen(addr.sun_path) + sizeof(addr.sun_family)) < 0) {
		printf("connect failed");
		return;
	}
	
	send(sock, string, strlen(string), 0);
	close(sock);
}

static int launch_daemon(int *pipefd, struct passwd *pwd) {
	pid_t pid;
	
	switch(pid = fork()) {
		case -1:
			return -1;
		case 0:
			setuid(pwd->pw_uid);
			setgid(pwd->pw_gid);
			seteuid(pwd->pw_uid);
			setegid(pwd->pw_gid);
			close(pipefd[0]);
			dup2(pipefd[1], STDOUT_FILENO);
			execl("/usr/local/bin/keyadd-daemon", "/usr/local/bin/keyadd-daemon", "--first-stage", NULL);
			return -1;
		default:
			close(pipefd[1]);
			return pid;
	}
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *handle, int flags, int argc, const char **argv) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc, const char **argv) {
	const char *pass;
	if(pam_get_authtok(handle, PAM_AUTHTOK , &pass, NULL) != PAM_SUCCESS) {
		printf("password fail\n");
		return PAM_AUTH_ERR;
	}
	strcpy(password, pass);
	
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *handle, int flags, int argc, const char *argv[]) {
	const char *username;
	struct passwd *pwd;
	char buf[257] = {};
	int fd;
	int pipefd[2];
	int status;
	pid_t pid;
	
	if(pam_get_user(handle, &username, NULL) != PAM_SUCCESS) {
		printf("username fail\n");
		return PAM_AUTH_ERR;
	}
	pwd = getpwnam(username);
	
	if(!*password) {
		printf("password fail\n");
		return PAM_AUTH_ERR;
	}
	
	pipe(pipefd);
	pid = launch_daemon(pipefd, pwd);
	fd = pipefd[0];
	
	do
		waitpid(pid, &status, 0);
	while(!WIFEXITED(status));
		
	if(WEXITSTATUS(status))
		return PAM_AUTH_ERR;
	
	read(fd, buf, 256);
	close(fd);
	*(strchr(buf, '\n')) = 0;
	pam_putenv(handle, buf);
	free(socket_filename);
	socket_filename = strdup(strchr(buf, '=') + 1);
	
	while(access(socket_filename, F_OK));
	
	seteuid(pwd->pw_uid);
	/*Send password over socket*/
	sprintf(buf, "password %s\n", password);
	socket_send_string(socket_filename, buf);
	seteuid(getuid());
	
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *handle, int flags, int argc, const char *argv[]) {
	/*Kill keyadd-daemon*/
	socket_send_string(socket_filename, "exit\n");
	return PAM_SUCCESS;
}


