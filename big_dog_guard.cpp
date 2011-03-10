/*
AUTHOR: JIEJUN ZHANG

big_dog_guard is a wrapper to a program, preventing it from damaging
the system and consuming too much resource.

RETURN VALUE SPECIFICATION
EXIT_FAILURE: Internal error occuerd, such as setrlimit() failed. The
              output to stdout is not guaranteed to be complete or
              correct. An ``Internal Error'' should be reported to the
              submitter

EXIT_SUCCESS: This program has done its jobs correctly. Its verdict
              , as NORMAL EXIT, SIGNALED, etc. to stdout is correct
              and complete.


Stdout contains the executing result:
+ Case 1: all is well
        NORMAL_EXIT
        [Time consumed (in second)] second
        [Memory consumed (int byte)] byte
        ^D

+ Case 2: program ended with non-zero return value
        NON-ZERO_RETURN_CODE
        [return value]
        ^D

    In this case, the verdict is not necessarily to be "runtime error",
    however I would recommend it.

+ Case 3: program is terminated by a signal
        SIGNALD
        [SIGNAL NAME]
        [SUGGESTED VERDICT: Runtime Error, Time Limit Exceeded, etc.]
        ^D

    In this case, a signal (except SIGTRAP, which triggers ptrace). Some
    signals are interpreted as particular verdict, as SIGKILL=MLE. Others
    are converted to signal name, as SIGPIPE, but not interpreted, so the
    last line would be empty.

+ Case 4: a prohibited system call is detected
        RESTRICTED_SYSCALL
        [SYSTEM CALL NAME]
        ^D

    In this case, child is killed.

+ Case 5: internal error: exec failed, setrlimit failed, etc.
    In this case, EXIT_FAILURE is returned. Messages in stdout is not
    guaranteed to be correct.

Stderr contains more detailed informations, which could also be showed to
the submitters, but it is intended to be debugging information.
*/

/*
TO-DOs:
+ setuid/setgui support
+ chroot support
+ a complete prohibited syscalls list
*/

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
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
char *executable = NULL;                    // the file to be executed
char **executable_argv = NULL;              // arguments provided to executable
char *input_file = NULL;                    // input file (for redirection)
char *output_file = NULL;                   // output file (for redirection)
char *stderr_file = NULL;                   // stderr file (for redirection)
rlim_t time_limit = 1;                      // time limit in second, default 1 second
rlim_t memory_limit = 128000000;            // memory limit in bytes, default 128M
uid_t uid;                                  // specified uid
gid_t gid;                                  // specified gid
bool prohibit_syscall = true;               // do we prohibit syscall?

int main(int argc, char *argv[]) {
    parse_args(argc, argv);

    pid_t child = fork();
    if (child == -1) {
        syslog("FATAL: fork() failed");
        exit(EXIT_FAILURE);
    }
    if(child == 0) {
        /* child process */
        if (input_file) {               // redirect input if specified
            int inf = open(input_file, O_RDONLY);
            dup2(inf, STDIN_FILENO);
            close(inf);
        }
        if (output_file) {              // redirect output if specified
            int outf = open(output_file, O_WRONLY | O_CREAT);
            chmod(output_file, 0666);
            dup2(outf, STDOUT_FILENO);
            close(outf);
        }
        if (stderr_file) {              // redirect stderr if specified
            int errf = open(stderr_file, O_WRONLY | O_CREAT);
            chmod(stderr_file, 0666);
            dup2(errf, STDERR_FILENO);
            close(errf);
        }
        if (enable_rlimit()) {          // setrlimit() and we are about to exec
            ptrace(PTRACE_TRACEME, 0, NULL, NULL);
            alarm(time_limit);
            execvp(executable, executable_argv);

            /* not reached or failed to execl */
            syslog("INTERNAL ERROR: execvp() failed.");
            raise(SIGUSR1);             // SIGUSR1: tell father that internal error occured
        } else {
            /* failed to set resource limit */
            syslog("INTERNAL ERROR: setrlimit() failed.");
            raise(SIGUSR1);             // SIGUSR1: tell father that internal error occured
        }
    } else {
        /* father process */
        while (true) {
            int status;
            wait(&status);
            if (WIFEXITED(status) || (WIFSTOPPED(status) && WSTOPSIG(status) == SIGCHLD)) {
                if (WIFSTOPPED(status) || WEXITSTATUS(status) == 0) {             // normal exit, report resource usage
                    syslog("program exited normally");
                    report("NORMAL_EXIT");
                    report_rusage();
                    exit(EXIT_SUCCESS);
                } else {                                    // non-zero returned
                    char buf[20];
                    sprintf(buf, "NON-ZERO_RETURN_CODE\n%d", WEXITSTATUS(status));
                    report(buf);
                    exit(EXIT_SUCCESS);
                }
            }
            if (WIFSIGNALED(status)) {      // true when and only when killed
                syslog("program killed");
                interpret_signal(WTERMSIG(status));
                exit(EXIT_SUCCESS);
            }
            if (WSTOPSIG(status) != SIGTRAP) {    // signaled, interpret signal
                syslog("program was signaled");
                interpret_signal(WSTOPSIG(status));
                exit(EXIT_SUCCESS);
                break;
            }
            int eax = ptrace(PTRACE_PEEKUSER, child, 4 * ORIG_EAX, NULL);
            if (prohibit_syscall && is_denied_syscall(eax)) {   // denined syscall kill the child
                syslog("FATAL: denied system call");
                ptrace(PTRACE_KILL, child, NULL, NULL);
                exit(EXIT_SUCCESS);
            }
            ptrace(PTRACE_SYSCALL, child, NULL, NULL);
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
        sprintf(buf, "%.3f second\n%ld bytes",
                (double)usage.ru_utime.tv_usec / 1000000.0,
                usage.ru_minflt * getpagesize()
        );
        report(buf);
    } else {
        /* WHAT'S THE F**K? */
        syslog("getrusage() failed");
        exit(EXIT_FAILURE);
    }
}

void parse_args(int argc, char *argv[]) {
    int tmp;
    executable = NULL;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--time") == 0 || strcmp(argv[i], "-t") == 0) {
            if (i + 1 == argc || sscanf(argv[i + 1], "%d", &tmp) != 1) {
                fprintf(stderr, "Invalid operand for time.\n");
                exit(EXIT_FAILURE);
            }
            time_limit = tmp;
            ++i;
        } else if (strcmp(argv[i], "--memory") == 0 || strcmp(argv[i], "-m") == 0) {
            if (i + 1 == argc || sscanf(argv[i + 1], "%d", &tmp) != 1) {
                fprintf(stderr, "Invalid operand for memroy.\n");
                exit(EXIT_FAILURE);
            }
            memory_limit = tmp;
            ++i;
        } else if (strcmp(argv[i], "--input") == 0 || strcmp(argv[i], "-i") == 0) {
            if (i + 1 == argc) {
                fprintf(stderr, "Missing operand for input.\n");
                exit(EXIT_FAILURE);
            }
            input_file = argv[++i];
        } else if (strcmp(argv[i], "--output") == 0 || strcmp(argv[i], "-o") == 0) {
            if (i + 1 == argc) {
                fprintf(stderr, "Missing operand for output.\n");
                exit(EXIT_FAILURE);
            }
            output_file = argv[++i];
        } else if (strcmp(argv[i], "--stderr") == 0 || strcmp(argv[i], "-e") == 0) {
            if (i + 1 == argc) {
                fprintf(stderr, "Missing operand for stderr.\n");
                exit(EXIT_FAILURE);
            }
            stderr_file = argv[++i];
        } else if (strcmp(argv[i], "--trust") == 0) {
            prohibit_syscall = false;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(EXIT_SUCCESS);
        } else if (argv[i][0] != '-') {
            executable = argv[i];
            executable_argv = &argv[i];
            break;
        } else {
            /* unrecognized option */
            fprintf(stderr, "Unrecognized option %s.\n", argv[i]);
            print_usage(EXIT_FAILURE);
        }
    }
    if (!executable) {
        report("No executable specified!");
        print_usage(EXIT_FAILURE);
    }
}

void print_usage(int exitcode) {
    puts("USAGE: big_dog_guard [options] program [program's args]");
    puts("AVAILABLE OPTIONS:");
    puts("  -h, --help\t\t\tprint help");
    puts("  -t, --time <second>\t\tspecify the maximum time executing child (default 1 second)");
    puts("  -m, --memory <byte>\t\tspecify the maximum memory child could use (default 1.28e9 bytes)");
    puts("  -i, --input <file>\t\tspecify the file from which stdin redrects");
    puts("  -o, --output <file>\t\tspecify the file to which stdout redrects");
    puts("  -e, --stderr <file>\t\tspecify the file to which stderr redrects");
    puts("  --trust\t\t\ttrust the program and do not deny any system call.");
    exit(exitcode);
}

void interpret_signal(int signal) {
    switch (signal) {
    case SIGKILL:
        report("SIGNALED\nSIGKILL\nMemory Limit Exceeded");
        break;
    case SIGFPE:
        report("SIGNALED\nSIGFPE\nRuntime Error (Floating-point exception)");
        break;
    case SIGSEGV:
        report("SIGNALED\nSIGSEGV\nRuntime Error (Segmentation violation)");
        break;
    case SIGXCPU:
        report("SIGNALED\nSIGXCPU\nTime Limit Exceeded");
        break;
    case SIGUSR1:
        syslog("INTERNAL ERROR (SIGUSR1 catched)");
        exit(EXIT_FAILURE);
        break;
    case SIGALRM:
        report("SIGNALED\nSIGALRM\ntTime Limit Exceeded");
        break;
    default:
        char buf[128] = "SIGNALED\n";
        strcat(buf, Tcl_SignalId(signal));
        strcat(buf, "\nunavailable");
        report(buf);
    }
}

int is_denied_syscall(int eax) {
    static int execve_cnt = 0;

    /* execve is supposed to be called once and only once */
    if (eax == SYS_execve && ++execve_cnt > 1) {
        report("RESTRICTED_SYSCALL\nexecve");
        return 1;
    }
    
    /* creating a child process is denied */
    if (eax == SYS_vfork || eax == SYS_fork || eax == SYS_clone) {
        report("RESTRICTED_SYSCALL\nfork/clone/vfork");
        return 1;
    }

    /* allowed */
    return 0;
}

