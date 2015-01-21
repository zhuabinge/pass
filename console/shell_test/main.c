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
#include <fcntl.h>
#include <sys/stat.h>

#define SH_RET  int
#define LEN (256)
#define SUCCESS 0
#define FAILURE 1
#define DEBUG 0


typedef struct passwd passwd_t;
typedef struct sigaction sigact_t;
typedef struct prm_s
{
    char *prm;
    char *input;
    char *cmd;
    char *para;
} prm_t;

typedef struct msgbuf_s
{
    long type;
    char msg[0];
} msgbuf_t;


prm_t *prompt;


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

    /*********************** test for rcv

    msgbuf_t *rcv = sh_calloc(bufsize);
    rcv->type = 1;
    if(msgrcv(msqid, rcv, bufsize, rcv->type, 0) == -1) {
        printf("msgrcv err\n");
        return FAILURE;
    }
    printf("rcv is------------------%s--------------------\n", rcv->msg);

    *************************************/

    return SUCCESS;
}


/*
 *
 *  exex builtin and external cmd
 *
 * */

SH_RET exec_cmd(prm_t *prompt)
{
    int status = 0;

    if(strcmp(prompt->cmd, "\n") == 0) goto L;

    /* builtin commands */
    if(strcmp(prompt->cmd, "restart") == 0 ) {
        snd_msg(prompt->cmd);
        goto L;
    }
    if(strcmp(prompt->cmd, "stop") == 0 ) {
        snd_msg(prompt->cmd);
        goto L;
    }

    if(strcmp(prompt->cmd, "help") == 0) {
        show_help();
        goto L;
    }

    /* external commands */
    if(fork() != 0) {

        /* parent process's executing codes */
        waitpid(0, &status, 0);

    } else {

        /* children process's executing code */

#if DEBUG
        printf("+++%s+++%s+++%02x+++%s+++\n", prompt->input, prompt->cmd, *(prompt->para), prompt->para);
#endif
        if(execl(prompt->cmd, prompt->cmd, (char *)0, (char *)0, (char *)0) != 0) {
            printf("%s: Not found\n", prompt->cmd);
            printf("Try \"help\" for more information\n");
        }
        exit(0);
    }
L:
    memset(prompt->cmd, 0, strlen(prompt->cmd));
    memset(prompt->para, '\0', strlen(prompt->para));
    return SUCCESS;
}


/*
 *
 *  read cmd and its paras from stdin, delete the spaces at head or tail of inputed commands
 *
 * */

SH_RET read_cmd(prm_t *prompt)
{
    char *tmp = NULL;
    char *p = NULL;
    u_char len = 0;
    u_char flag = 0;
    u_char n = 0;

    tmp = readline(prompt->prm);

    if(tmp[0] == '\0') return FAILURE;

    if(tmp[0] == ' ') flag = 1;

    prompt->input = tmp + flag;
    flag = 0;

    if(prompt->input[strlen(prompt->input) - 1] == ' ')
        prompt->input[strlen(prompt->input) - 1] = '\0';

    p = prompt->input;
    for(n = 0; n < strlen(prompt->input); n++) {
        if(*p != ' ') {
            len++;
            p++;
        }
    }

    memcpy(prompt->cmd, prompt->input, len);

    if (len != strlen(prompt->input))
        memcpy(prompt->para, p + 1, strlen(prompt->input) - (len + 1));

    add_history(tmp);
    free(tmp);

    return SUCCESS;
}


/*
 *
 *  show customized prompt on stdout
 *
 * */

SH_RET type_prm(prm_t *prompt)
{
    snprintf(prompt->prm, 256, "[%s@%s ~#] ", "admin", "t410");
    return SUCCESS;
}


/*
 *
 * block signal sigquit and sigint
 *
 * */

void sh_sig_blk_ct()
{
    printf("\n%s", prompt->prm);
}


SH_RET sh_init(prm_t *prompt)
{
    prompt->prm = sh_calloc(LEN);
    prompt->input = sh_calloc(LEN);
    prompt->cmd = sh_calloc(LEN);
    prompt->para = sh_calloc(LEN);

    return SUCCESS;
}


SH_RET main()
{
    prompt = sh_calloc(sizeof(prm_t));
    sigact_t act;

    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    act.sa_handler = sh_sig_blk_ct;
    sigaction(SIGINT, &act, NULL);
    //sigaction(SIGQUIT, &act, NULL);

    sh_init(prompt);

    while(1){

        /* show the prompt on the console */
        type_prm(prompt);
        /* read commands from standard input */
        if(read_cmd(prompt) == FAILURE) continue;

        /* execute commands read passed from read_cmd() */
        exec_cmd(prompt);

    }

    return SUCCESS;
}
