#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sched.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/syscall.h>

#ifndef CLONE_NEWNS
#	define CLONE_NEWNS 0x00020000 /* New mount namespace group */
#endif
#ifndef CLONE_NEWCGROUP
#	define CLONE_NEWCGROUP 0x02000000 /* New cgroup namespace */
#endif
#ifndef CLONE_NEWUTS
#	define CLONE_NEWUTS 0x04000000 /* New utsname namespace */
#endif
#ifndef CLONE_NEWIPC
#	define CLONE_NEWIPC 0x08000000 /* New ipc namespace */
#endif
#ifndef CLONE_NEWUSER
#	define CLONE_NEWUSER 0x10000000 /* New user namespace */
#endif
#ifndef CLONE_NEWPID
#	define CLONE_NEWPID 0x20000000 /* New pid namespace */
#endif
#ifndef CLONE_NEWNET
#	define CLONE_NEWNET 0x40000000 /* New network namespace */
#endif

#define SYS_PIVOT_ROOT    155
#define pivot_root(new_root,put_old) syscall(SYS_PIVOT_ROOT,new_root,put_old)

#define HOST_NAME  "MyContainer"
#define HOST_NAME_LEN  12

#define STACK_SIZE 8*1024
#define ROOT_PATH "/home/dai/rootfs"

// pid isolation, needs flag CLONE_NEWPID,
// so you will see getpid is 0 and getppid is 0
void get_container_pid()
{
    printf("this is child container, pid is:%d, parent id is:%d\n", getpid(), getppid());
}

// host name isolation, needs flag CLONE_NEWUTS
// so child hostname will set to "HOST_NAME"
void set_host_name()
{
    sethostname(HOST_NAME, HOST_NAME_LEN);
    char host[100];
    gethostname(host, sizeof(host));
    printf("container host name is:%s\n", host);
}

int prepare_root()
{

    // if pivot fail, maybe you have shared mount points
    // run "grep -iP '/ /\s' /proc/$$/mountinfo" to see if there is shared info
    // run "unshare -m" to unshare mounts namespace, or pivot will not work!!
    if (mount(ROOT_PATH, ROOT_PATH, "", MS_BIND|MS_REC, NULL) != 0)
    {
        printf("MS_BIND|MS_REC mount rootfs %s fail because: %s [%d]\n", ROOT_PATH, strerror(errno), errno);
        return -1;
    }

    return 0;
}

int mount_dev(const char* source, char* target, const char* type, unsigned long flag, char* data)
{
    struct stat buffer;
    char path[50];
    sprintf(path, "%s/%s", ROOT_PATH, target);
    printf("path: %s\n", path);

    if (stat(path, &buffer) != 0)
    {
        mkdir(path, 0755);
    }
    if (mount(source, path, type, flag, data) != 0)
    {
        printf("mount %s fail because: %s [%d]\n", source, strerror(errno), errno);
        return -1;
    }

    return 0;
}

// rootfs isolation, needs flag CLONE_NEWNS
int mount_to_rootfs()
{

    unsigned long defaultMountFlags = MS_NOEXEC | MS_NOSUID | MS_NODEV;

    if (mount_dev("proc", "proc", "proc", defaultMountFlags, NULL) !=0)
    {
        return -1;
    }

    if (mount_dev("sysfs", "sys", "sysfs", defaultMountFlags|MS_RDONLY, NULL) !=0)
    {
        return -1;
    }

    if (mount_dev("mqueue", "dev/mqueue", "mqueue", defaultMountFlags, NULL) !=0)
    {
        return -1;
    }

    if (mount_dev("tmpfs", "dev", "tmpfs", MS_NOSUID|MS_STRICTATIME, "mode=755") !=0)
    {
        return -1;
    }

    if (mount_dev("devpts", "dev/pts", "devpts", MS_NOSUID|MS_NOEXEC, "newinstance,ptmxmode=666,gid=5,mode=620") !=0)
    {
        return -1;
    }

    if (mount_dev("shm", "dev/shm", "tmpfs", defaultMountFlags, "mode=1777,size=65536k") !=0)
    {
        return -1;
    }

    return 0;
}

int move_rootfs()
{
    if (chdir(ROOT_PATH) != 0)
    {
        printf("chdir fail because: %s [%d]\n", strerror(errno), errno);
        return -1;
    }

    if (mount(ROOT_PATH, "/", "", MS_MOVE, NULL) != 0)
    {
        printf("MS_MOVE mount %s fail because: %s [%d]\n", ROOT_PATH, strerror(errno), errno);
        return -1;
    }

    if (chroot(".") != 0)
    {
        printf("chroot fail because: %s [%d]\n", strerror(errno), errno);
        return -1;
    }

    if (chdir("/") != 0)
    {
        printf("chdir fail because: %s [%d]\n", strerror(errno), errno);
        return -1;
    }

    return 0;
}

int pivot_rootfs()
{
    if (chdir(ROOT_PATH) != 0)
    {
        printf("chdir fail because: %s [%d]\n", strerror(errno), errno);
        return -1;
    }

    struct stat buffer;
    char putold_path[50];
    sprintf(putold_path, "%s/%s", ROOT_PATH, "putold");
    printf("putold path: %s\n", putold_path);

    if (stat(putold_path, &buffer) != 0)
    {
        mkdir(putold_path, 0700);
    }

    if (pivot_root(ROOT_PATH, "/home/dai/rootfs/putold") != 0)
    {
        printf("pivot_root fail because: %s [%d]\n", strerror(errno), errno);
        return -1;
    }

    if (chdir("/") != 0)
    {
        printf("chdir fail because: %s [%d]\n", strerror(errno), errno);
        return -1;
    }

    const char* putold = "putold";

    if (umount2(putold, MNT_DETACH) != 0)
    {
        printf("umount2 putold fail because: %s [%d]\n", strerror(errno), errno);
        return -1;
    }

    rmdir(putold);

    return 0;
}

int child_container()
{
    get_container_pid();

    set_host_name();

    if (prepare_root() != 0){exit(1);}

    if (mount_to_rootfs() != 0){exit(1);}

    //if (move_rootfs() != 0){exit(1);}
    if (pivot_rootfs() != 0){exit(1);}

    // run bash
    char* env[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "TERM=xterm", NULL};
    execle("/bin/bash", NULL, env);

    exit(0);
}

void main()
{
    void *stack;
    int result;

    char host[100];
    if (gethostname(host, sizeof(host)) < 0)
    {
        printf("get host name error\n");
        exit(1);
    }

    printf("this is parent, host name is:%s\n", host);

    result = system("brctl addbr enn0");
    printf("this is parent brctl result is %d\n",result);

    stack = malloc(STACK_SIZE);
    if (!stack)
    {
        printf("stack failed\n");
        exit(1);
    }

    int flag = CLONE_NEWUTS|CLONE_NEWPID|CLONE_NEWIPC|CLONE_NEWNS|CLONE_NEWNET;
    int pid = clone(&child_container, (char *)stack + STACK_SIZE, flag|SIGCHLD, 0);
    if (pid < 0)
    {
        printf("clone child error pid is:%d\n", pid);
        exit(1);
    }
    printf("this is parent, child pid is:%d, parent pid id is:%d\n", pid, getpid());


    waitpid(pid,NULL,0);
    free(stack);

    exit(0);

}