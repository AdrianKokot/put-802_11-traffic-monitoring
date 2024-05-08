/*
 * Compilation: gcc -I . -Wall ./main.c -o ./main -lpcap
 */

#include <pcap.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stdint.h>
#include <unistd.h>
#include "structs.h"
#include "hwutils.h"
#include "printutils.h"

char *errbuf = NULL;
pcap_t *handle = NULL;
com_ap_data_list *ap_list = NULL;

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

  bpf_u_int32 netp, maskp;
  struct bpf_program fp;

  char *interface = argv[1];

  errbuf = malloc(PCAP_ERRBUF_SIZE);
  handle = pcap_create(interface, errbuf);

  if (pcap_set_promisc(handle, 1) != 0)
  {
    printf("Failed to set monitor mode.\n");
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

  pcap_lookupnet(interface, &netp, &maskp, errbuf);
  pcap_compile(handle, &fp, "type mgt subtype beacon || type data subtype data", 0, maskp);

  if (pcap_setfilter(handle, &fp) < 0)
  {
    pcap_perror(handle, "pcap_setfilter()");
    exit(EXIT_FAILURE);
  }

  if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO)
  {
    printf("Wrong datalink type\n");
    exit(EXIT_FAILURE);
  }

  ap_list = com_ap_data_list_new();
  printf("Starting...\n");
  pcap_loop(handle, -1, main_loop, NULL);

  return 0;
}

void cleanup()
{
  if (handle != NULL)
  {
    pcap_close(handle);
  }

  if (errbuf != NULL)
  {
    free(errbuf);
  }

  if (ap_list != NULL)
  {
    for (int i = 0; i < ap_list->size; i++)
    {
      free(ap_list->data[i]);
      ap_list->data[i] = NULL;
    }

    free(ap_list);
    ap_list = NULL;
  }
}

void stop(int signum)
{
  exit(EXIT_SUCCESS);
}

void main_loop(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
  radiotap_header *rdiohdr;
  rdiohdr = (radiotap_header *)(bytes);

  const uint8_t *frame_control_byte = bytes + rdiohdr->it_len;
  frame_control *fc = (frame_control *)(frame_control_byte);

  uint8_t *source_address, *destination_address, *bssid;
  mac_header *hdr = (mac_header *)(frame_control_byte);

  if (fc->to_ds == 0)
  {
    destination_address = hdr->address1;

    if (fc->from_ds == 0)
    {
      source_address = hdr->address2;
      bssid = hdr->address3;
    }
    else
    {
      source_address = hdr->address3;
      bssid = hdr->address2;
    }
  }
  else
  {
    destination_address = hdr->address3;

    if (fc->from_ds == 0)
    {
      source_address = hdr->address2;
      bssid = hdr->address1;
    }
    else
    {
      source_address = hdr->address1;
      bssid = hdr->address2;
    }
  }

  if (fc->type == 0 && fc->subtype == 0b1000)
  {
    beacon_frame_body *beacon_frame = (beacon_frame_body *)(bytes + rdiohdr->it_len + sizeof(mac_header));

    char ssid[33];
    memcpy(ssid, beacon_frame->ssid.ssid, beacon_frame->ssid.length);
    ssid[beacon_frame->ssid.length] = '\0';

    int found = 0;

    for (int i = 0; i < ap_list->size; i++)
    {
      if (mac_equal(ap_list->data[i]->bssid, bssid))
      {
        found = 1;
        break;
      }
    }

    if (!found)
    {
      com_ap_data *data = com_ap_data_new(bssid, ssid);
      com_ap_data_list_add(ap_list, data);
    }

    return;
  }

  if (!(fc->type == 0b10 && fc->subtype == 0b0000))
  {
    return;
  }

  if (mac_is_broadcast(destination_address))
  {
    return;
  }

  com_ap_data *current_ap = NULL;

  for (int i = 0; i < ap_list->size; i++)
  {
    if (mac_equal(ap_list->data[i]->bssid, bssid))
    {
      current_ap = ap_list->data[i];
      break;
    }
  }

  if (current_ap == NULL)
  {
    return;
  }

  int found = 0;

  for (int i = 0; i < current_ap->size; i++)
  {
    centry *entry = &current_ap->entries[i];
    if ((mac_equal(entry->addr_1, source_address) && mac_equal(entry->addr_2, destination_address)) || (mac_equal(entry->addr_2, source_address) && mac_equal(entry->addr_1, destination_address)))
    {
      entry->ttl = START_TTL;
      found = 1;
      break;
    }
  }

  if (!found)
  {
    com_ap_data_add_entry(current_ap, source_address, destination_address, START_TTL);
  }

  clear();

  for (int i = 0; i < ap_list->size; i++)
  {
    com_ap_data *data = ap_list->data[i];
    printf("BSSID: " GREEN MACSTR RESET " SSID: " BLUE "%s" RESET "\n", MAC2STR(data->bssid), data->ssid);
    for (int j = 0; j < data->size; j++)
    {
      centry *entry = &data->entries[j];
      printf("\t%d. "GREEN MACSTR YELLOW" <-> "GREEN MACSTR RESET"\n", j + 1, MAC2STR(entry->addr_1), MAC2STR(entry->addr_2));
      entry->ttl--;
    }

    remove_old_entries(ap_list->data[i]);

    printf("\n");
  }
}
