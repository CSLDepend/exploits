/*
 * $Id: login.h, this is just login client
 */

#ifndef LOGIN_H
#define LOGIN_H
#ifndef __ASSEMBLY__
int	client_login(char *host, char *cmd);

#endif
#define SHELL_INTERACTIVE 0
#define SHELL_NONINTERACTIVE 1
#define SHELL_UPLOAD 2
#define SHELL_DOWNLOAD 3
#endif
