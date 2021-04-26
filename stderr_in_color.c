#include <ctype.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

char *color;
const void *color_code, *end_color_code;
size_t color_code_len, end_color_code_len;
bool is_bash;

/*
 * set_color_codes setups global variables indicating color codes
 */
void set_color_codes()
{
  /*
   * hash is djb2 hash function by Dan Bernstein with minor modifications
   * original: cse.yorku.ca/~oz/hash.html
   */
  long hash(char *str) {
    long hash = 5381;
    int c;
    while ((c = *str++)) {
      hash = ((hash << 5) + hash) + c;  /* hash * 33 + c */
    }
    return hash;
  }

  /*
   * lower returns lowercased string from the given string
   */
  char *lower(char *str) {
    for(int i = 0; str[i]; i++) {
      str[i] = tolower(str[i]);
    }
    return str;
  }

  color = getenv("STDERR_COLOR");
  /*
   * Switch statement doesn't support string data type hence
   * in order to keep switch statement clarity precalculated hashes are used instead.
   */
  switch (hash(lower(color))) {
  case 210707760194:  /* black */
    color_code = "\x1b[30m";
    break;

  case 210713909846:  /* green */
    color_code = "\x1b[32m";
    break;

  case 6954248304353:  /* yellow */
    color_code = "\x1b[33m";
    break;

  case 6385084301:  /* blue */
    color_code = "\x1b[34m";
    break;

  case 229474533704194:  /* magenta */
    color_code = "\x1b[35m";
    break;

  case 6385133744:  /* cyan */
    color_code = "\x1b[36m";
    break;

  case 210732530054:  /* white */
    color_code = "\x1b[37m";
    break;

  default:  /* red */
    color_code = "\x1b[31m";
  }

  color_code_len = strlen(color_code);
  end_color_code = "\x1b[0m";
  end_color_code_len = strlen(end_color_code);
}

/*
 * set_is_bash checks if current process is bash and
 * if so sets is_bash global variable to true
 */
void set_is_bash()
{
  pid_t pid = getpid();
  char path[18];
  sprintf(path, "%s%d%s", "/proc/", pid, "/comm");
  FILE *stream = fopen(path, "r");

  char context[5];
  fgets(context, 5, stream);
  if (strcmp(context, "bash") == 0) {
    is_bash = true;
  }
  fclose(stream);
}

/*
 * init function executes when shared library is loaded
 */
__attribute__((constructor)) void init()
{
  set_color_codes();
  set_is_bash();
}

int execve(const char *pathname, char *const argv[], char *const envp[])
{
  if (is_bash && !fork()) {
    pid_t tracee_pid = getppid();
    bool written_color_code;
    int wstatus;
    ptrace(PTRACE_ATTACH, tracee_pid, NULL, NULL);
    while(1) {
      waitpid(tracee_pid, &wstatus, 0);

      if (written_color_code) {
        write(STDOUT_FILENO, end_color_code, end_color_code_len);
        written_color_code = false;
      }

      if (wstatus == -1) {
        exit(EXIT_FAILURE);
      }
      if (WIFEXITED(wstatus)) {
        exit(EXIT_SUCCESS);
      }

      struct user_regs_struct regs;
      ptrace(PTRACE_GETREGS, tracee_pid, NULL, &regs);
      if (regs.orig_rax == SYS_write && regs.rdi == STDERR_FILENO) {
        write(STDERR_FILENO, color_code, color_code_len);
        written_color_code = true;
      }

      ptrace(PTRACE_SYSCALL, tracee_pid, NULL, NULL);
    }
  } else {
    int (*original_execve)() = (int (*)())dlsym(RTLD_NEXT, "execve");
    int status = original_execve(pathname, argv, envp);
    return status;
  }
  return 0;
}
