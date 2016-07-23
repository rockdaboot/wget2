#include "utils.h"

#include <config.h>
#include <libwget.h>
# include <sys/ioctl.h>
# include <termios.h>

/* Determine the width of the terminal we're running on.  If that's
   not possible, return 0.  */
int
determine_screen_width (void)
{
  /* If there's a way to get the terminal size using POSIX
     tcgetattr(), somebody please tell me.  */
  int fd;
  struct winsize wsz;

  fd = fileno (stderr);
  if (ioctl (fd, TIOCGWINSZ, &wsz) < 0)
    return 0;                   /* most likely ENOTTY */

  return wsz.ws_col;
}
