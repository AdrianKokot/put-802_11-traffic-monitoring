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
#include <stdint.h>

char *errbuf;
pcap_t *handle;

void main_loop(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void cleanup();
void stop(int signum);

typedef struct frame_control
{
  uint8_t version : 2;
  uint8_t type : 2;
  uint8_t subtype : 4;
  uint8_t to_ds : 1;
  uint8_t from_ds : 1;
  uint8_t more_frag : 1;
  uint8_t retry : 1;
  uint8_t pwr_mgt : 1;
  uint8_t more_data : 1;
  uint8_t wep : 1;
  uint8_t order : 1;
} frame_control;

typedef struct mac_header
{
  uint8_t frame_control[2];
  uint8_t duration_id[2];
  uint8_t address1[6]; // Destination MAC address
  uint8_t address2[6]; // Source MAC address
  uint8_t address3[6]; // BSSID
  uint8_t sequence_control[2];
  // Add other fields as needed
} mac_header;
// Function to parse the MAC header
mac_header parse_mac_header(const uint8_t *mac_header_bytes)
{
  mac_header hdr;
  memcpy(hdr.frame_control, mac_header_bytes, 2);
  memcpy(hdr.duration_id, mac_header_bytes + 2, 2);
  memcpy(hdr.address1, mac_header_bytes + 4, 6);
  memcpy(hdr.address2, mac_header_bytes + 10, 6);
  memcpy(hdr.address3, mac_header_bytes + 16, 6);
  memcpy(hdr.sequence_control, mac_header_bytes + 24, 2);
  // Copy other fields as needed
  return hdr;
}

frame_control parse_frame_control(const uint8_t *frame_control_byte)
{
  frame_control fc;
  fc.version = (*frame_control_byte) & 0x03;
  fc.type = ((*frame_control_byte) >> 2) & 0x03;
  fc.subtype = ((*frame_control_byte) >> 4) & 0x0F;
  fc.to_ds = ((*frame_control_byte) >> 8) & 0x01;
  fc.from_ds = ((*frame_control_byte) >> 9) & 0x01;
  fc.more_frag = ((*frame_control_byte) >> 10) & 0x01;
  fc.retry = ((*frame_control_byte) >> 11) & 0x01;
  fc.pwr_mgt = ((*frame_control_byte) >> 12) & 0x01;
  fc.more_data = ((*frame_control_byte) >> 13) & 0x01;
  fc.wep = ((*frame_control_byte) >> 14) & 0x01;
  fc.order = ((*frame_control_byte) >> 15) & 0x01;
  return fc;
}

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

void main_loop(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
  const uint8_t *frame_control_byte = bytes;
  frame_control fc = parse_frame_control(frame_control_byte);

  const uint8_t *mac_header_bytes = bytes;
  mac_header hdr = parse_mac_header(mac_header_bytes);

  // Print the MAC addresses

  // Print the parsed frame control fields
  printf("Version: %u, Type: %u, Subtype: %u\n", fc.version, fc.type, fc.subtype);
  printf("To DS: %u, From DS: %u, More Frag: %u\n", fc.to_ds, fc.from_ds, fc.more_frag);
  printf("Retry: %u, Power Management: %u, More Data: %u\n", fc.retry, fc.pwr_mgt, fc.more_data);
  printf("WEP: %u, Order: %u\n", fc.wep, fc.order);

  printf("Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", hdr.address1[0], hdr.address1[1], hdr.address1[2], hdr.address1[3], hdr.address1[4], hdr.address1[5]);
  printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", hdr.address2[0], hdr.address2[1], hdr.address2[2], hdr.address2[3], hdr.address2[4], hdr.address2[5]);
  printf("BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n", hdr.address3[0], hdr.address3[1], hdr.address3[2], hdr.address3[3], hdr.address3[4], hdr.address3[5]);

  printf("\n\n\n");
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

  // if (pcap_can_set_rfmon(handle) == 0)
  // {
  //   printf("Monitor mode can not be set.\n");
  //   exit(EXIT_FAILURE);
  // }

  // if (pcap_set_rfmon(handle, 1) != 0)
  // {
  //   printf("Failed to set monitor mode.\n");
  //   exit(EXIT_FAILURE);
  // }

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
