#line 1 "Tweak.xm"


#import <substrate.h>

#if !defined(PT_DENY_ATTACH)
#define PT_DENY_ATTACH 31
#endif

static int (*_ptraceHook)(int request, pid_t pid, caddr_t addr, int data); 

static int $ptraceHook(int request, pid_t pid, caddr_t addr, int data) {

       
        if (request == PT_DENY_ATTACH) { 
        request = -1; 
        }
        return _ptraceHook(request,pid,addr,data);  
}

static __attribute__((constructor)) void _logosLocalCtor_e641bec3(int __unused argc, char __unused **argv, char __unused **envp) {
        MSHookFunction((void *)MSFindSymbol(NULL,"_ptrace"), (void *)$ptraceHook, (void **)&_ptraceHook);
}

