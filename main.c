/*
 * Compilation: gcc -Wall ./main.c -o ./main -lpcap
 */

#include <pcap.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

char *errbuf;
pcap_t *handle;

void main_loop(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void cleanup();
void stop(int signum);

int main(int argc, char *argv[])
{
  atexit(cleanup);
  signal(SIGINT, stop);

  if (argc != 2)
  {
    printf("Usage: %s <interface>\n", argv[0]);
    return 1;
  }

  char *interface = argv[1];

  errbuf = malloc(PCAP_ERRBUF_SIZE);
  handle = pcap_create(interface, errbuf);

  if (pcap_can_set_rfmon(handle) == 0)
  {
    printf("Monitor mode can not be set.\n");
    exit(EXIT_FAILURE);
  }

  if (pcap_set_rfmon(handle, 1) != 0)
  {
    printf("Failed to set monitor mode.\n");
    exit(EXIT_FAILURE);
  }

  pcap_set_snaplen(handle, 65535);
  pcap_set_timeout(handle, 1000);

  if (pcap_activate(handle) != 0)
  {
    printf("pcap_activate() failed\n");
    exit(EXIT_FAILURE);
  }

  // pcap_set_rfmon(handle, 1);

  // pcap_activate(handle);
  pcap_loop(handle, -1, main_loop, NULL);

  return 0;
}

typedef struct mac_header
{
  // Mandatory
  unsigned char frame_control[2];
  // Mandatory
  unsigned char id[2];
  // Optional
  unsigned char address_1[6];
  // Optional
  unsigned char address_2[6];
  // Optional
  unsigned char address_3[6];
  // Optional
  unsigned char sequence_control[2];
  // Optional
  unsigned char address_4[6];
  // Optional
  unsigned char qos_control[2];
  // Optional
  unsigned char ht_control[4];
} mac_header;

/**
 * struct ieee80211_radiotap_header - base radiotap header
 *
 * source: https://github.com/radiotap/radiotap-library/blob/master/radiotap.h
 */
struct ieee80211_radiotap_header
{
  /**
   * @it_version: radiotap version, always 0
   */
  uint8_t it_version;

  /**
   * @it_pad: padding (or alignment)
   */
  uint8_t it_pad;

  /**
   * @it_len: overall radiotap header length
   */
  uint16_t it_len;

  /**
   * @it_present: (first) present word
   */
  uint32_t it_present;
};

// #include <stdio.h>
// #include <sys/types.h>
// #include <sys/stat.h>
// #include <sys/mman.h>
// #include <fcntl.h>
// #include <unistd.h>
// #include <endian.h>
// #include <errno.h>
// #include <string.h>
// #include <pcap/pcap.h>

/**
 * https://en.wikipedia.org/wiki/802.11_frame_types
 */
typedef struct frame_control
{
  unsigned protocol : 2;
  unsigned type : 2;
  unsigned subtype : 4;
  unsigned to_ds : 1;
  unsigned from_ds : 1;
  unsigned more_frag : 1;
  unsigned retry : 1;
  unsigned pwr_mgt : 1;
  unsigned more_data : 1;
  unsigned wep : 1;
  unsigned order : 1;
} frame_control;

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

void main_loop(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
  struct ieee80211_radiotap_header *radiotap;
  radiotap = (struct ieee80211_radiotap_header *)bytes;
  mac_header *mac = (mac_header *)(bytes + radiotap->it_len);

  printf("\tsource address: " MACSTR "\n", MAC2STR(mac->address_2));
  printf("\tdestination address: " MACSTR "\n", MAC2STR(mac->address_1));
  printf("\tbssid: " MACSTR "\n", MAC2STR(mac->address_3));
}

void cleanup()
{
  pcap_close(handle);
  free(errbuf);
}

void stop(int signum)
{
  exit(EXIT_SUCCESS);
}