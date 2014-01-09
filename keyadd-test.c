#include <stdlib.h>
#include <stdio.h>
#include <gnome-keyring.h>

int main(int argc, char **argv) {
	GnomeKeyringResult result;
	guint32 item_id;
	
	result = gnome_keyring_set_network_password_sync(
		NULL,
		"username",
		NULL,
		"server.org",
		NULL,
		"sftp",
		"password",
		0,
		"this-is-the-password",
		&item_id
	);
	
	if(result != GNOME_KEYRING_RESULT_OK)
		printf("keyring fail %u: %s\n", result, gnome_keyring_result_to_message(result));
	return 0;
}
