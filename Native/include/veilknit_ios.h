#ifndef VEILKNIT_IOS_H
#define VEILKNIT_IOS_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

bool weave_veilknit_start(const char *data_directory, bool signup, const char *username, const char *password);
bool weave_veilknit_send_command(const char *command);
bool weave_veilknit_request_stop(void);
bool weave_veilknit_is_running(void);
char *weave_veilknit_restore_backup(const char *data_directory, const char *backup_path, const char *passphrase);
char *weave_veilknit_drain_logs(void);
char *weave_veilknit_transact(const char *request_json);
char *weave_veilknit_recover_app_credential(const char *app_id);
uint64_t weave_veilknit_subscribe(const char *request_json);
char *weave_veilknit_drain_subscription(uint64_t subscription_id);
bool weave_veilknit_subscription_active(uint64_t subscription_id);
char *weave_veilknit_profile_id(void);
bool weave_veilknit_unsubscribe(uint64_t subscription_id);
void weave_veilknit_string_free(char *value);

#ifdef __cplusplus
}
#endif

#endif
