#ifndef _PRINTUTILS_H
#define _PRINTUTILS_H

void clear() {
  printf("\033[H\033[J");
}

#define GREEN "\033[0;32m]"
#define YELLOW "\033[0;33m"
#define RED "\033[0;31m"
#define BLUE "\033[0;34m"

#define RESET "\033[0m"

#endif