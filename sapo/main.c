#include <stdio.h>
#include <string.h>
#include "ps_sapo.h"

int main(int argc, char *argv[]) {
    // help global
    if (argc < 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        printf("use: sapo [subcomando] [flags]\n");
        printf("subcommands availables:\n");
        printf("  ps       view running processes.\n");
        printf("  find     view running processes that match the given pattern.\n");
        printf("  files    shows all files that are open.\n");
        printf("  ports    shows open TCP and UDP ports.\n");
        printf("  kill     send a signal to a given process.\n");
        printf("\nuse 'sapo [subcommand] -h/--help' to view help for a specific command.\n");
        return 0;
    }

    // ps
    if (strcmp(argv[1], "ps") == 0) {
        int all_flag = 0;
        
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--all") == 0) {
                all_flag = 1;
            } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "help") == 0) {
                printf("use: sapo ps [-a | --all]\n");
                printf("shows the processes of the current user. with -a or --all shows everyone's\n");
                return 0;
            }
        }

        ps_exec(all_flag, NULL);

    // find
    } else if (strcmp(argv[1], "find") == 0) {
        if (argc < 3 || strcmp(argv[2], "-h") == 0 || strcmp(argv[2], "--help") == 0) {
            printf("use: sapo find <pattern>\n");
            printf("shows the current running user's current processes that match the given pattern.\n");
            return 0;
        }
        ps_exec(1, argv[2]);

    // files
    } else if (strcmp(argv[1], "files") == 0){
        if (argc < 3 || strcmp(argv[2], "-h") == 0 || strcmp(argv[2], "--help") == 0) {
            printf("use: sapo files <PID>\n");
            printf("shows all files that are open and/or used by that process.\n");
            return 0;
        }
        files_exec(argv[2]);
    
    // kill
    } else if (strcmp(argv[1], "kill") == 0){
        if (argc < 3 || strcmp(argv[2], "-h") == 0 || strcmp(argv[2], "--help") == 0) {
            printf("use: sapo kill [-s <SIGNAL>] <PID>\n");
            printf("send a signal to a given process.\n");
            return 0;
        }
        const char *pid_t = NULL;
        const char *sig_t = NULL;

        if (strcmp(argv[2], "-s") == 0) {
            if (argc < 5) {
                fprintf(stderr, "error: PID not specified.\n");
                return 1;
            }
            sig_t= argv[3];
            pid_t= argv[4];
        } else {
            pid_t = argv[2];
            sig_t = NULL;
        }

        kill_exec(pid_t, sig_t);
    // ports
    } else if (strcmp(argv[1], "ports") == 0){
        if (argc >= 3 && (strcmp(argv[2], "-h") == 0 || strcmp(argv[2], "--help") == 0)) {
            printf("use: sapo ports\n");
            printf("shows the open TCP and UDP ports, indicating which process is using them.\n");
            return 0;
        }
        ports_exec();
    }
    else {
        fprintf(stderr, "error: command '%s' not reconigzed.\n", argv[1]);
        printf("use 'sapo --help' to see the list of valid commands.\n");
        return 1;
    }

    return 0;
}