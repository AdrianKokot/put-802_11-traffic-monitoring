#ifndef _HWUTILS_H
#define _HWUTILS_H

#include <stdint.h>

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

int mac_equal(const uint8_t *mac1, const uint8_t *mac2)
{
  return memcmp(mac1, mac2, 6) == 0;
}

int mac_is_broadcast(const uint8_t *mac)
{
  return mac[0] == 0xff && mac[1] == 0xff && mac[2] == 0xff && mac[3] == 0xff && mac[4] == 0xff && mac[5] == 0xff;
}

#endif