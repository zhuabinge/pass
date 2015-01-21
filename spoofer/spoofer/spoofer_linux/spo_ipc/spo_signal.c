#include "../../spoofer_system/spoofer.h"
#include "../spo_linux.h"
#include <signal.h>



__sighandler_t spo_signal(int sig, __sighandler_t handler)
{
    return signal(sig,  handler);
}


SPO_RET_VALUE spo_sigaction(int sig, const struct sigaction *act, struct sigaction *oact)
{
    return sigaction(sig, act, oact);
}


/**
 *
 *  signal a sig use sigaction
 *
 *  @param sig, is the sig to add.
 *
 *  @param func, is the func when sig come, we call it.
 *
 *  @return int, is the exec status.
 *
 **/

SPO_RET_STATUS spo_signal_a_sig(int sig, spo_sa_sigaction func)
{
    struct sigaction act, oact;

    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    act.sa_sigaction = func;

    sigaction(sig, &act, &oact);

    return SPO_OK;
}


/**
 *
 *  del a sig in a sigset.
 *
 *  @param sig, is the sig we have to del.
 *
 *  @param set, the set we have to op.
 *
 *  @return int, is the exec status.
 *
 **/

SPO_RET_STATUS spo_del_sig_in_set(int sig, sigset_t *set)
{
    if (sig <= 0 || sig > 64 || set == NULL) return SPO_FAILURE;

    if (sigismember(set, sig) == 1) {
        if (sigdelset(set, sig) == -1) {
#if SPO_DEBUG
            perror("del sig err\n");
#endif
            return SPO_FAILURE;
        }
    }else {
#if SPO_DEBUG
        perror("sig no a member in this set\n");
#endif
        return SPO_FAILURE;
    }

    return SPO_OK;
}


/**
 *
 *  add a sig to a set.
 *
 * */

SPO_RET_STATUS spo_add_sig_to_set(int sig, sigset_t *set)
{
    if (sig <= 0 || sig > 64 || set == NULL) return SPO_FAILURE;

    if (sigaddset(set, sig) == -1) {
#if SPO_DEBUG
        perror("add err : \n");
#endif
        return SPO_FAILURE;
    }

    return SPO_OK;
}


/**
 *
 *  fill a sigset.
 *
 *  @param set, is the sigset, we have to fill.
 *
 *  @return int, is the exec status.
 *
 **/

SPO_RET_STATUS spo_fill_sigmask(sigset_t *set)
{
    if (set == NULL) return SPO_FAILURE;

    if (sigfillset(set) == -1) {
#if SPO_DEBUG
        perror("fill set err\n");
#endif
        return SPO_FAILURE;
    }

    return SPO_OK;
}


/**
 *
 *  mask all sig and signal it.
 *
 *  @return int, is the exec status.
 *
 **/

SPO_RET_STATUS spo_mask_all_sig()
{
    int ret = 0;
    sigset_t set, oset;

    memset(&set, '\0', sizeof(sigset_t));
    memset(&oset, '\0', sizeof(sigset_t));

    ret = spo_fill_sigmask(&set);
    if (ret == SPO_FAILURE) return SPO_FAILURE;

    ret = sigprocmask(SIG_SETMASK, &set, &oset);
    if (ret == -1) {
#if SPO_DEBUG
        perror("mask all sig err\n");
#endif
        return SPO_FAILURE;
    }

    return SPO_OK;
}


/**
 *
 *  signal a sigset.
 *
 *  @param set, is the sigset we have to signal.
 *
 *  @return int, is the exec status.
 *
 **/

SPO_RET_STATUS spo_signal_a_sigset(sigset_t *set)
{
    int ret = 0;
    sigset_t oset;

    if (set == NULL) return SPO_FAILURE;

    ret = sigprocmask(SIG_SETMASK, set, &oset);

    if (ret == -1) {
#if SPO_DEBUG
        perror("signal sigset err\n");
#endif
        return SPO_FAILURE;
    }

    return SPO_OK;
}
