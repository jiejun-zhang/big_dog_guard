/*
AUTHOR: JIEJUN ZHANG

big_dog_guard is a wrapper to a program, preventing it from damaging
the system and consuming too much resource.

This program traces all system calls the child process made, and
dangerous system calls are denied. Moreover, child process are
started with specified uid and gid.

This program returns EXIT_SUCCESS when and only when the child terminated
normally (i.e. not killed, no prohibited syscalls, etc.)

Stdout contains the executing result:
+ Case 1: all is well
        NORMAL EXIT
        time: [Time consumed (in second)]
        memory: [Memory consumed (int byte)]
        ^D

+ Case 2: program ended with non-zero return value
        [return value] RETURNED
        ^D

    In this case, the verdict is not necessarily to be "runtime error",
    however I would recommend it.

+ Case 3: program is terminated by a signal
        SIGNALD:\t\t[SIGNAL NAME]
        SUGGESTED VERDICT:\t[VERDICT: Runtime Error, Time Limit Exceeded, etc.]
        ^D

    In this case, a signal (except SIGTRAP, which triggers ptrace). Some
    signals are interpreted as particular verdict, as SIGKILL=MLE. Others
    are converted to signal name, as SIGPIPE, but not interpreted, so the
    second line would be:
    SUGGESTED VERDICT:\tunavailable

+ Case 4: a prohibited system call is detected
        PROHIBITED SYSTEM CALL: [SYSTEM CALL NAME]
        ^D

    In this case, the more detailed information

Stderr contains more detailed informations, which could also be showed to
the submitters, but it is intended to be debugging information.
*/

/*
TO-DOs:
+ input/output redirection
+ setuid/setgui support
+ chroot support
+ a complete prohibited syscalls list
*/

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <tcl.h>                            // convert signal code to readable string

void report(const char *str);               // report our verdict
void syslog(const char *str);
int is_denied_syscall(int eax);             // being called every time a syscall is detected
int enable_rlimit();                        // enable the resource limit
void report_rusage();                       // report the resource usage
void interpret_signal(int signal);          // interpret the signal which killed the child
void parse_args(int argc, char *argv[]);    // parse command-line arguments
void print_usage(int exit_code);            // print usage

char default_root_dir[] = "./";
char *root_dir = default_root_dir;          // the root dir
char *executable = 0;                       // the file to be executed
rlim_t time_limit = 1;                      // time limit in second, default 1 second
rlim_t memory_limit = 128000000;            // memory limit in bytes, default 128M
uid_t uid;                                  // specified uid
gid_t gid;                                  // specified gid

int main(int argc, char *argv[]) {
    parse_args(argc, argv);

    pid_t child = fork();
    if (child == -1) {
        syslog("FATAL: fork() failed");
        exit(EXIT_FAILURE);
    }
    if(child == 0) {
        if (enable_rlimit()) {
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            execl("./test", "test", 0);

            /* not reached or failed to execl */
            syslog("INTERNAL ERROR: execl() failed.");
            exit(EXIT_FAILURE);
        } else {
            /* failed to set resource limit */
            syslog("INTERNAL ERROR: setrlimit() failed.");
            exit(EXIT_FAILURE);
        }
    } else {
        while (true) {
            int status;
            wait(&status);
            if (WIFEXITED(status)) {
                if (WEXITSTATUS(status) == 0) {             // normal exit, report resource usage
                    syslog("program exited normally");
                    report_rusage();
                    exit(EXIT_SUCCESS);
                } else {                                    // non-zero returned
                    char buf[20];
                    sprintf(buf, "%d RETURNED", WEXITSTATUS(status));
                    report(buf);
                    report("SUGGESTED VERDICT: Runtime Error (non-zero return)");
                    exit(EXIT_FAILURE);
                }
            }
            if (WIFSIGNALED(status)) {      // true when and only when killed
                syslog("program killed");
                interpret_signal(WTERMSIG(status));
                exit(EXIT_FAILURE);
            }
            if (WSTOPSIG(status) != 5) {    // signaled, interpret signal
                syslog("program was signaled");
                interpret_signal(WSTOPSIG(status));
                exit(EXIT_FAILURE);
                break;
            }
            int eax = ptrace(PTRACE_PEEKUSER, child, 4 * ORIG_EAX, 0);
            if (is_denied_syscall(eax)) {   // denined syscall kill the child
                syslog("FATAL: denied system call");
                ptrace(PTRACE_KILL, child, 0, 0);
                exit(EXIT_FAILURE);
            }
            ptrace(PTRACE_SYSCALL, child, 0, 0);
        }
    }
    return EXIT_SUCCESS;
}

void report(const char msg[]) {
    fprintf(stdout, "%s\n", msg);
}

void syslog(const char msg[]) {
    time_t raw_time;
    char buf[256];
    time(&raw_time);
    strcpy(buf, ctime(&raw_time));
    buf[strlen(buf) - 1] = '\0';
    fprintf(stderr, "[ %s ] %s\n", buf, msg);
}

int enable_rlimit() {
#   define APPLY(type, value) \
        getrlimit(type, &lim);\
        lim.rlim_cur = (value);\
        if (setrlimit(type, &lim) != 0) {\
            return 0;\
        }
    struct rlimit lim;
    APPLY(RLIMIT_CPU, time_limit);          // time limit
    APPLY(RLIMIT_AS, memory_limit);         // memory limit
    return 1;
#   undef APPLY
}

void report_rusage() {
    struct rusage usage;
    if (getrusage(RUSAGE_CHILDREN, &usage) == 0) {
        char buf[128];
        sprintf(buf, "time: %.3f second\nspace: %ld bytes",
                (double)usage.ru_utime.tv_usec / 1000000.0,
                usage.ru_minflt * getpagesize()
        );
        report(buf);
    } else {
        report("time: unavailable\nmemory: unavailable");
    }
}

void parse_args(int argc, char *argv[]) {
    int tmp;
    executable = 0;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--time") == 0 || strcmp(argv[i], "-t") == 0) {
            if (i + 1 == argc || sscanf(argv[i + 1], "%d", &tmp) != 1) {
                print_usage(EXIT_FAILURE);
            }
            time_limit = tmp;
            ++i;
        } else if (strcmp(argv[i], "--memory") == 0 || strcmp(argv[i], "-m") == 0) {
            if (i + 1 == argc || sscanf(argv[i + 1], "%d", &tmp) != 1) {
                print_usage(EXIT_FAILURE);
            }
            memory_limit = tmp;
            ++i;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(EXIT_SUCCESS);
        } else if (argv[i][0] != '-') {
            if (executable) {
                print_usage(EXIT_FAILURE);
            }
            executable = argv[i];
        }
    }
}

void print_usage(int exitcode) {
    puts("USAGE: big_dog_guard [options] program");
    puts("AVAILABLE OPTIONS:");
    puts("  -t, --time <second>\t\tspecify the maximum time executing child (default 1 second)");
    puts("  -m, --memory <byte>\t\tspecify the maximum memory child could use (default 1.28e9 bytes)");
    exit(exitcode);
}

void interpret_signal(int signal) {
    switch (signal) {
    case SIGKILL:
        report("SIGNALED:\t\tSIGKILL\nSUGGESTED VERDICT:\tMemory Limit Exceeded");
        break;
    case SIGFPE:
        report("SIGNALED:\t\tSIGFPE\nSUGGESTED VERDICT:\tRuntime Error (Floating-point exception)");
        break;
    case SIGSEGV:
        report("SIGNALED:\t\tSIGSEGV\nSUGGESTED VERDICT:\tRuntime Error (Segmentation violation)");
        break;
    case SIGXCPU:
        report("SIGNALED:\t\tSIGXCPU\nSUGGESTED VERDICT:\tTime Limit Exceeded");
        break;
    default:
        char buf[128] = "SIGNALED: ";
        strcat(buf, Tcl_SignalId(signal));
        report(buf);
    }
}

int is_denied_syscall(int eax) {
    static int execve_cnt = 0;

    /* execve is supposed to be called once and only once */
    if (eax == SYS_execve && ++execve_cnt > 1) {
        report("PROHIBITED SYSTEM CALL: execve");
        return 1;
    }
    
    /* creating a child process is denied */
    if (eax == SYS_vfork || eax == SYS_fork || eax == SYS_clone) {
        report("PROHIBITED SYSTEM CALL: fork/clone/vfork");
        return 1;
    }

    /* allowed */
    return 0;
}

