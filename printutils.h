#ifndef _PRINTUTILS_H
#define _PRINTUTILS_H

void clear() {
  printf("\033[H\033[J");
}

#define GREEN "\033[1;92m"
#define YELLOW "\033[1;93m"
#define RED "\033[1;91m"
#define BLUE "\033[1;94m"
#define CYAN "\033[1;96m"

#define RESET "\033[0m"

#endif
