#include "ps_sapo.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <pwd.h>
#include <ctype.h>
#include <regex.h>
#include <signal.h>

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef __NR_pidfd_send_signal
#define __NR_pidfd_send_signal 424
#endif

// fns auxiliares
const char* get_username(uid_t uid) {
    struct passwd *pw = getpwuid(uid);
    if (pw){
        return pw->pw_name;
    } else {
        return "unknown";
    }
}

int ver_pid(const char *str) {
    for (int i = 0; str[i] != '\0'; i++) {
        if (!isdigit(str[i])) 
            return 0;
    }
    return 1;
}
// ps
void ps_exec(int vall, const char *pattern) {
    struct dirent *entry;
    uid_t my_uid = getuid();

    DIR *dir;
    dir = opendir("/proc"); // open dir /proc

    // compilación de la expr regular
    regex_t regex; 
    int regex_exec;
    if (pattern != NULL){
        regex_exec = 1;
        if (regcomp(&regex, pattern, REG_EXTENDED | REG_NOSUB | REG_ICASE) != 0) {
            fprintf(stderr, "error, pattern invalid '%s'\n", pattern);
            closedir(dir);
            return;
        }
    }else{
        regex_exec = 0;
    }

    // TABLE
    printf("%-8s %-18s %-20s %-s\n", "PID", "USER", "PROCESS NAME", "COMMAND");
    printf("-------------------------------------------------------------------\n");

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR && ver_pid(entry->d_name)) { // solo nos importa la carpeta "DT_DIR"
            char path[512];           
            snprintf(path, sizeof(path), "/proc/%s/status", entry->d_name);

            FILE *fp;
            fp = fopen(path, "r");

            char line[256];
            char process_name[256];
            uid_t uid_process;

            while (fgets(line, sizeof(line), fp)) { // leemos dentro de status
                if (strncmp(line, "Name:", 5) == 0) {  // buscamos el nombre
                    sscanf(line, "Name:\t%s", process_name);
                } else if (strncmp(line, "Uid:", 4) == 0) { // buscamos el uid del proceso
                    sscanf(line, "Uid:\t%d", &uid_process);
                }
            }
            fclose(fp);

            if (!vall && uid_process != my_uid) { //aquí se apĺica la flag -a 
                continue; // si entra al if continúa con el sig proceso
            }

            snprintf(path, sizeof(path), "/proc/%s/cmdline", entry->d_name); // para buscar el comando invocado
            fp = fopen(path, "r"); // abrimos el archivo cmdline
            char cmd[512]; 
            
            if (fp) {
                size_t read_bytes = fread(cmd, 1, sizeof(cmd) - 1, fp); // leemos el 1 byte del archivo
                fclose(fp);
                
                if (read_bytes > 0) {
                    for (size_t i = 0; i < read_bytes - 1; i++) {
                        if (cmd[i] == '\0'){ // ya que linux separa cada palabra con \0
                            cmd[i] = ' '; // reemplazamos por espacio vacío
                        } 
                    }
                    cmd[read_bytes] = '\0'; // marcamos el final 
                } 
            }
            // find
            if (regex_exec) {
                int name_pattern = (regexec(&regex, process_name, 0, NULL, 0) == 0); // comparamos el patron con el nombre del proceso
                int cmd_pattern = (regexec(&regex, cmd, 0, NULL, 0) == 0); // comparamos el patron con el nombre del comando

                if (!name_pattern && !cmd_pattern) {
                    continue;
                }
            }

            printf("%-8s %-18s %-20s %-s\n", 
                   entry->d_name, 
                   get_username(uid_process), 
                   process_name, 
                   cmd);
        }
    }
    closedir(dir);
}
// files
void files_exec(const char *pid){
    char path[512];
    // estoy asumiendo que es un pid válido, si no igual saltará el mensaje de error
    snprintf(path, sizeof(path), "/proc/%s/fd", pid);

    DIR *direct = opendir(path); // abrimos el fd del pid entregado
    if(!direct){
        fprintf(stderr, "error: wrong PID\n");
        return;
    }

    printf("%-8s %-s\n", "PID", "FILE");
    printf("-------------------------------------------------------------------\n");

    struct dirent *entry; 
    while ((entry = readdir(direct)) != NULL) {
        char symlink[1024];
        char real_path[1024];

        snprintf(symlink, sizeof(symlink), "%s/%s", path, entry->d_name); // construimos la ruta

        ssize_t len = readlink(symlink, real_path, sizeof(real_path) - 1); // leemos el texto que está dentro del link simbólico
        if (len != -1) {
            real_path[len] = '\0';
            printf("%-8s %-s\n", entry->d_name, real_path);
        }
    }
    closedir(direct);
}

// ports
// función auxiliar que nos ayude a cruzar la información
int inodes_proc(char *process_name, size_t name_len, unsigned long inode){
    DIR *dir = opendir("/proc");
    
    struct dirent *s_proc;
    int proc_f = -1;
    // este es el patron que buscamos
    char pattern_socket[64];
    snprintf(pattern_socket, sizeof(pattern_socket), "socket:[%lu]", inode);

    // ahora buscarémos en todo /proc carpetas de PIDS
    while ((s_proc = readdir(dir)) != NULL) {
        if (s_proc->d_type == DT_DIR && ver_pid(s_proc->d_name)){
            char fd_root[512];
            snprintf(fd_root, sizeof(fd_root), "/proc/%s/fd", s_proc->d_name);

            DIR *dir_fd = opendir(fd_root); 
            // caso que no podamos acceder a la ruta
            if(!dir_fd){
                continue;
            }
            
            // hay que recorrer dentro de los fds del archivo dentro de la ruta fd_root
            struct dirent *s_fd;
            while((s_fd = readdir(dir_fd)) != NULL) {
                // hay que fijarse que no entre en los directorio reales . y ..
                if (strcmp(s_fd->d_name, ".") == 0 || strcmp(s_fd->d_name, "..") == 0) {
                    continue;
                }
                char link_root[1024];
                snprintf(link_root, sizeof(link_root), "%s/%s", fd_root, s_fd->d_name);

                char link_dest[512];

                ssize_t len = readlink(link_root, link_dest, sizeof(link_dest) - 1);
                
                if (len != -1) {
                    link_dest[len] = '\0'; 

                    if (strcmp(link_dest, pattern_socket) == 0) {
                        proc_f = atoi(s_proc->d_name);
                        
                        // buscamos el nombre del proceso
                        char ruta_comm[512];
                        snprintf(ruta_comm, sizeof(ruta_comm), "/proc/%s/comm", s_proc->d_name);
                        FILE *f_comm = fopen(ruta_comm, "r");

                        if (f_comm) {
                            if (fgets(process_name, name_len, f_comm)) {
                                int indc = strcspn(process_name, "\n");
                                process_name[indc] = '\0';
                            }
                            fclose(f_comm);
                        } else {
                            strncpy(process_name, "unknown", name_len);
                        }
                        
                        closedir(dir_fd);
                        closedir(dir);
                        return proc_f;
                    }
                }
            }
            closedir(dir_fd);
        }
    }
    
    closedir(dir);
    return -1;
}

void read_ports(const char *arch_root, const char *protocole_name) {
    FILE *file = fopen(arch_root, "r");

    char line[1024];
    // debemos saltar la primera linea
    if (!fgets(line, sizeof(line), file)) {
        fclose(file);
        return;
    }

    // leemos las conexiones reales
    while (fgets(line, sizeof(line), file)) {
        unsigned int hex_port;
        unsigned long inodo = 0;
        unsigned int ip;
        int flag_read;

        char line_copy[1024];
        strcpy(line_copy, line);

        char *token;
        token = strtok(line_copy, " \t\n");
        int col = 0;
        
        while (token != NULL) {
            col++;
            // col 2 -> contiene "IP_LOCAL:PUERTO_HEX"
            if (col == 2) {
                if (sscanf(token, "%X:%X", &ip, &hex_port) == 2) {
                    flag_read = 1; 
                }
            }
            // col 10 -> contiene inodo
            if (col == 10) {
                inodo = strtoul(token, NULL, 10);
                break;
            }

            token = strtok(NULL, " \t\n");
        }

        
        if (flag_read && inodo > 0) { // esto lo usamos para transformar la ip de formato hex a algo leible por humanos
            unsigned char b1 = (ip & 0xFF);
            unsigned char b2 = ((ip >> 8) & 0xFF);
            unsigned char b3 = ((ip >> 16) & 0xFF);
            unsigned char b4 = ((ip >> 24) & 0xFF);

            char ip_final[64];
            snprintf(ip_final, sizeof(ip_final), "%d.%d.%d.%d", b1, b2, b3, b4); // aquí reconstruimos la ip

            char process_name[256];
            int pid = inodes_proc(process_name, sizeof(process_name), inodo); // hacemos llamado a la fn aux para que enlace los inodos con sus ids respectivos

            if (pid != -1) {
                printf("%-15s %-20s %-8d %-s\n", protocole_name, ip_final, pid, process_name);
            } else {
                printf("%-15s %-20s %-8s %-s\n", protocole_name, ip_final, "-", "-");
            }
        }
    }
    fclose(file);
}

void ports_exec(void){
    printf("%-15s %-20s %-8s %-s\n", "PROTOCOLO", "LOCAL_ADDRESS", "PID", "PROCESS NAME");
    printf("------------------------------------------------------------------------------------\n");

    // TCP
    read_ports("/proc/net/tcp", "TCP");
    
    // UDP
    read_ports("/proc/net/udp", "UDP");
}

// kill
int signals(const char *signal){
    if(signal == NULL){
        return SIGTERM;
    }
    if(ver_pid(signal)){ //verificamos si la señal es un numero o string
        int num_signal = atoi(signal);
        if (num_signal >= 1 && num_signal <= 64){
            return num_signal;
        }
        return -1;
    }
    const char *signals_name[] = { // diccionario con las señales
        "", "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT", 
        "SIGBUS", "SIGFPE", "SIGKILL", "SIGUSR1", "SIGSEGV", "SIGUSR2", 
        "SIGPIPE", "SIGALRM", "SIGTERM", "SIGSTKFLT", "SIGCHLD", "SIGCONT", 
        "SIGSTOP", "SIGTSTP", "SIGTTIN", "SIGTTOU", "SIGURG", "SIGXCPU", 
        "SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH", "SIGIO", "SIGPWR", "SIGSYS"
    };
    
    for (int i = 1; i <= 31; i++) { // convertimos todas las señales a su número respectivo
        if (strcmp(signal, signals_name[i]) == 0) {
            return i;
        }
    }

    int offset = 0;
    // ej: SIGRTMIN+8
    if (strncasecmp(signal, "SIGRTMIN", 8) == 0) { //aquí trabajamos con las señales especiales
        if (sscanf(signal + 8, "%d", &offset) == 1) {
            int result = SIGRTMIN + offset;
            if (result >= SIGRTMIN && result <= SIGRTMAX){
                return result;
            }
            return -1;
        }
        return SIGRTMIN;
    }
    // ej: SIGRTMAX-8
    if (strncasecmp(signal, "SIGRTMAX", 8) == 0) { //aquí trabajamos con las señales especiales
        if (sscanf(signal + 8, "%d", &offset) == 1) {
            int result = SIGRTMAX + offset;
            if (result >= SIGRTMIN && result <= SIGRTMAX){
                return result;
            }
            return -1;
        }
        return SIGRTMAX;
    }
    return -1;
}

void kill_exec(const char *pid, const char *signal){
    //primero verificamos si existe tal pid
    if (!ver_pid(pid)) {
        fprintf(stderr, "error: invalid pid '%s'\n", pid);
        return;
    }
    
    int pid_num = atoi(pid); // convertimos el pid al entero
    int signal_val = signals(signal); // convertimos la señal a su número respectivo

    if (signal_val == -1){
        fprintf(stderr, "error: signal '%s' not recognized.\n", signal);
        return;
    }
    // llamada a sistema 
    int pid_call = syscall(__NR_pidfd_open, pid_num, 0); 
    int value = syscall(__NR_pidfd_send_signal, pid_call, signal_val, NULL, 0);
    if (value == -1){
        perror("error: send signal failed");

    }else{
        printf("signal %d sent successfully to PID %d.\n", signal_val, pid_num);
    }

    close(pid_call);
}
