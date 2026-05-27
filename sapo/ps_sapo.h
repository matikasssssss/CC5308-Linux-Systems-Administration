#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef PS_SAPO_H
#define PS_SAPO_H

#include <sys/types.h>

void ps_exec(int vall, const char *pattern);
void files_exec(const char *pid);
void kill_exec(const char *pid, const char *signal);
void ports_exec();
void read_ports(const char *arch_root, const char *protocole_name);

int inodes_proc(char *process_name, size_t name_len, unsigned long inode);
int ver_pid(const char *str);
const char* get_username(uid_t uid);

#endif