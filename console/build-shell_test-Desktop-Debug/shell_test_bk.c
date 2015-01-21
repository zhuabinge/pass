#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <pwd.h>
#include <wait.h>
#include <readline/readline.h>
#include <readline/history.h>

#define SH_RET  int
#define LEN (128)
#define SUCCESS 0
#define FAILURE 1


typedef struct passwd passwd_t;
typedef struct sigaction sigact_t;
typedef struct prompt_s
{
    char *user;
    char *host;
    char *path;
    char *symbol;
} prompt_t;

typedef struct msgbuf_s
{
    long type;
    char msg[0];
} msgbuf_t;

prompt_t *prompt;

/*
 *
 *  malloc and memset zero for a pointer
 *
 * */

void *sh_calloc(size_t size)
{
    void *p;
    if((p = malloc(size)) == NULL)
        return NULL;

    memset(p, '\0', size);

    return p;
}

SH_RET show_help()
{
    printf("halt \t\t turn off the machine\n");
    printf("reboot \t\t reboot the machine\n");
    printf("shutdown \t close the process\n");
    printf("restart \t restart the process\n");
    return SUCCESS;
}

/*
 *
 *  send mdg to spoofer
 *
 * */

SH_RET snd_msg(char *cmd)
{
    int msqid = 123456;
    size_t bufsize = sizeof(msgbuf_t) + LEN;
    msgbuf_t *buf = sh_calloc(bufsize);
    buf->type = 1;
    memcpy(buf->msg, cmd, strlen(cmd));

    if((msqid = msgget((key_t )msqid, 0666 | IPC_CREAT)) == -1) {
        printf("msgid creation err\n");
        return FAILURE;
    }

    if(msgsnd(msqid, buf, bufsize, 0) == -1) {
        printf("msgsnd err\n");
        return FAILURE;
    }

    //***********************test for rcv

    msgbuf_t *rcv = sh_calloc(bufsize);
    rcv->type = 1;
    if(msgrcv(msqid, rcv, bufsize, rcv->type, 0) == -1) {
        printf("msgrcv err\n");
        return FAILURE;
    }
    printf("rcv is------------------%s--------------------\n", rcv->msg);

    return SUCCESS;
}

/*
 *
 *  exex builtin and external cmd
 *
 * */

SH_RET exec_cmd(char *cmd, char *para)
{
    int status = 0;

    para = para;

    // builtin cmds
    if(strcmp(cmd, "restart-spo") == 0 ) {
        snd_msg(cmd);
        return SUCCESS;
    }
    if(strcmp(cmd, "shutdown-spo") == 0 ) {
        snd_msg(cmd);
        return SUCCESS;
    }

    if(strcmp(cmd, "help") == 0) {
        show_help();
        return SUCCESS;
    }

    // external cmds
    if(fork() != 0) {

        //p_code
        waitpid(0, &status, 0);

    } else {

        //c_code
        if(execlp(cmd, cmd, (char *)0, (char *)0, (char *)0) != 0) {
            printf("%s: Not found\n", cmd);
            printf("Try \"help\" for more information\n");
        }

    }

    return SUCCESS;
}

/*
 *
 *  read cmd and its paras from stdin
 *
 * */

SH_RET read_cmd(char *cmd, char *para, prompt_t *prompt)
{
    u_char len = 0;
    char input = '\0';
    para = para;

    input = getchar();
    if(input == '\n') {
        printf("\n[%s@%s %s%s] ", prompt->user, prompt->host, prompt->path, prompt->symbol);
        return FAILURE;

    }

    while(len < LEN && input != '\n') {

        cmd[len++] = input;
        input = getchar();
    }

    return SUCCESS;
}

/*
 *
 *  show customized prompt on stdout
 *
 * */

SH_RET type_prompt(prompt_t *prompt)
{
    prompt = sh_calloc(sizeof(prompt_t));

    //    prompt->host = sh_calloc(LEN);
    //    prompt->path = sh_calloc(LEN);
    //    prompt->user = sh_calloc(LEN);

    //    passwd_t *pw = getpwuid(getuid());
    //    u = pw->pw_name;

    //    gethostname(h, sizeof(h));

    //    getcwd(p, sizeof(p));

    prompt->host = "t410";
    prompt->path = "~";
    prompt->user = "root";

    if(strcmp(prompt->user, "root") == 0) prompt->symbol = "#";

    printf("[%s@%s %s%s] ", prompt->user, prompt->host, prompt->path, prompt->symbol);
    return SUCCESS;
}

/*
 *
 * block signal sigquit and sigint
 *
 * */

void blkact(int sig)
{

    //    if(sig == SIGINT) printf("^C");
    //    if(sig == SIGQUIT) printf("^\\");
    printf("[%s@%s %s%s] ", prompt->user, prompt->host, prompt->path, prompt->symbol);


}

SH_RET main()
{
    char *cmd = sh_calloc(LEN);
    // ***************************************save paras
    char para[LEN] = {'\0'};

    type_prompt(prompt);                                //prompt to stdout
    sigact_t act, oact;
    sigset_t set, sysset;
    sigemptyset(&set);

    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGQUIT);

    sigprocmask(SIG_SETMASK, &set, NULL);
    act.sa_handler = blkact;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);

    sigaction(SIGINT, &act, &oact);
    sigaction(SIGQUIT, &act, &oact);


    while(1) {

        if (read_cmd(cmd, para, prompt) == FAILURE) continue;                               //read cmd from stdin

        //if(strlen(cmd) != 0) printf("cmd is %s\n", cmd);

        if(exec_cmd(cmd, para) == FAILURE) {
            printf("exec_cmd err\n");
            return FAILURE;
        }

        type_prompt(prompt);                                //prompt to stdout
        memset(cmd, '\0', LEN);

    }

    //**********************************************free pointer
    return SUCCESS;
}
