//
//  main.m
//  AttachDemo
//
//  Created by clf on 2018/6/29.
//  Copyright © 2018年 clf. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"

#import <dlfcn.h>

#import <sys/types.h>

//int main(int argc, char * argv[]) {
//    @autoreleasepool {
//        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
//    }
//}


#pragma mark --加入Ptrace检测，防止白盒测试、逆向工程对源代码进行调试

typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);

#if !defined(PT_DENY_ATTACH)

#define PT_DENY_ATTACH 31

#endif

void disable_gdb() {

    void* handle = dlopen(0, RTLD_GLOBAL | RTLD_NOW);

    ptrace_ptr_t ptrace_ptr = dlsym(handle, "ptrace");

    ptrace_ptr(PT_DENY_ATTACH, 0, 0, 0);

    dlclose(handle);

}

int main(int argc, char * argv[]) {

    @autoreleasepool {

#ifndef DEBUG

        disable_gdb();


#endif

        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));

    }

}
