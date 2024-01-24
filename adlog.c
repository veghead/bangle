// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#define VERSION "0.1"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <signal.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include "hciwrap.h"
#include "cJSON.h"

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#define CONFIG_BUFFER 4096

/* Unofficial value, might still change */
#define LE_LINK 0x80

#define FLAGS_AD_TYPE 0x01
#define FLAGS_LIMITED_MODE_BIT 0x01
#define FLAGS_GENERAL_MODE_BIT 0x02

#define EIR_FLAGS 0x01		   /* flags */
#define EIR_UUID16_SOME 0x02   /* 16-bit UUID, more available */
#define EIR_UUID16_ALL 0x03	   /* 16-bit UUID, all listed */
#define EIR_UUID32_SOME 0x04   /* 32-bit UUID, more available */
#define EIR_UUID32_ALL 0x05	   /* 32-bit UUID, all listed */
#define EIR_UUID128_SOME 0x06  /* 128-bit UUID, more available */
#define EIR_UUID128_ALL 0x07   /* 128-bit UUID, all listed */
#define EIR_NAME_SHORT 0x08	   /* shortened local name */
#define EIR_NAME_COMPLETE 0x09 /* complete local name */
#define EIR_TX_POWER 0x0A	   /* transmit power level */
#define EIR_DEVICE_ID 0x10	   /* device ID */

#define for_each_opt(opt, long, short) while ((opt = getopt_long(argc, argv, short ? short : "+", long, NULL)) != -1)

#define MAX_IFS 16

typedef struct
{
	char *addr;
	uint16_t angle;
	char *name;
	int dev_id;
} if_desc;

typedef struct mac_filter
{
    char *filter;
    struct mac_filter *next;
} mac_filter_t;

typedef struct
{
	mac_filter_t *mac_filters;
	if_desc interfaces[MAX_IFS];
	uint8_t num_interfaces;
} hciconfig;

static volatile int signal_received = 0;
static int config_verbose = 0;
static bool config_daemon = false;

static void usage(void);


static inline int8_t get_s8(const void *ptr)
{
    return *((int8_t *) ptr);
}

static void sigint_handler(int sig)
{
	signal_received = sig;
}

static int str2buf(const char *str, uint8_t *buf, size_t blen)
{
	int i, dlen;

	if (str == NULL)
		return -EINVAL;

	memset(buf, 0, blen);

	dlen = MIN((strlen(str) / 2), blen);

	for (i = 0; i < dlen; i++) {
		sscanf(str + (i * 2), "%02hhX", &buf[i]);
    }

	return 0;
}

static int dev_info(int s, int dev_id, long arg)
{
	struct hci_dev_info di = {.dev_id = dev_id};
	char addr[18];

	if (ioctl(s, HCIGETDEVINFO, (void *)&di))
		return 0;

	ba2str(&di.bdaddr, addr);
	printf("\t%s\t%s\n", di.name, addr);
	return 0;
}

static void hex_dump(char *pref, int width, unsigned char *buf, int len)
{
	register int i, n;

	for (i = 0, n = 1; i < len; i++, n++)
	{
		if (n == 1)
			printf("%s", pref);
		printf("%2.2X ", buf[i]);
		if (n == width)
		{
			printf("\n");
			n = 0;
		}
	}
	if (i && n != 1)
		printf("\n");
}

/* Display local devices */

static struct option dev_options[] = {
	{"help", 0, 0, 'h'},
	{0, 0, 0, 0}};

/* Inquiry */

static int print_advertising_devices(int dd, uint8_t filter_type, if_desc *iface, mac_filter_t *filters)
{
	unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
	struct hci_filter nf, of;
	socklen_t olen;
	int len;

	olen = sizeof(of);
	if (getsockopt(dd, SOL_HCI, HCI_FILTER, &of, &olen) < 0)
	{
		printf("Could not get socket options\n");
		return -1;
	}

	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
	hci_filter_set_event(EVT_LE_META_EVENT, &nf);

	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0)
	{
		printf("Could not set socket options\n");
		return -1;
	}

	while (signal_received != SIGINT)
	{
		evt_le_meta_event *meta;
		le_advertising_info *info;
		char addr[18];

		while ((len = read(dd, buf, sizeof(buf))) < 0)
		{
			if (errno == EINTR && signal_received == SIGINT)
			{
				len = 0;
				goto done;
			}

			if (errno == EAGAIN || errno == EINTR)
				continue;
			goto done;
		}

		ptr = buf + (1 + HCI_EVENT_HDR_SIZE);
		len -= (1 + HCI_EVENT_HDR_SIZE);

		meta = (void *)ptr;

		if (meta->subevent != 0x02)
			goto done;

		info = (le_advertising_info *)(meta->data + 1);
		char name[30];

		memset(name, 0, sizeof(name));

		ba2str(&info->bdaddr, addr);
        mac_filter_t *f = filters;
        bool found = false;
        while(f) {
            if (strcasestr(addr, f->filter) == addr) {
                found = true;
                break;
            }
            f = f->next;
        }
        if (!found) continue;
	    printf("%s:", addr);
        for (int i = 0; i< info->length; i++) {
            printf("%02X", info->data[i]);
        }
        int8_t rssi = get_s8(info->data + info->length);
        printf(",%d\n", rssi);
		syslog(LOG_INFO, "%s,%s,%d,%d", iface->addr, addr, iface->angle, rssi);
	}

done:
	setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));

	if (len < 0)
		return -1;

	return 0;
}

static void lescan(if_desc *iface, mac_filter_t* filter)
{
	int err, opt, dd;
	uint8_t own_type = LE_PUBLIC_ADDRESS;
	uint8_t scan_type = 0x00;
	uint8_t filter_type = 0;
	uint8_t filter_policy = 0x00;
	uint16_t interval = htobs(0x0010);
	uint16_t window = htobs(0x0010);
	uint8_t filter_dup = 0x01;

	dd = hci_open_dev(iface->dev_id);
	if (dd < 0)
	{
		perror("Could not open device");
		exit(1);
	}

	err = hci_le_set_scan_parameters(dd, scan_type, interval, window,
									 own_type, filter_policy, 10000);
	if (err < 0)
	{
		perror("Set scan parameters failed");
		exit(1);
	}

	err = hci_le_set_scan_enable(dd, 0x01, filter_dup, 10000);
	if (err < 0)
	{
		perror("Enable scan failed");
		exit(1);
	}

	err = print_advertising_devices(dd, filter_type, iface, filter);
	if (err < 0)
	{
		perror("Could not receive advertising events");
		exit(1);
	}

	err = hci_le_set_scan_enable(dd, 0x00, filter_dup, 10000);
	if (err < 0)
	{
		perror("Disable scan failed");
		exit(1);
	}

	hci_close_dev(dd);
}

static void usage(void)
{
	int i;

	printf("adlog - Multi HCI BLE scanner %s\n", VERSION);
	printf("Usage:\n"
		   "\tbangle [options] -c <config file> [-d] [-v]\n");
	printf("Options:\n"
		   "\t-h\tDisplay help\n"
		   "\t-v\tVerbose\n"
		   "\t-d\tRun as daemon\n");
}

static struct option main_options[] = {
	{"help", 0, 0, 'h'},
	{"device", 1, 0, 'i'},
	{0, 0, 0, 0}};

static void load_interfaces_from_json(hciconfig *config, cJSON *if_list)
{
	cJSON *ifp;
	uint8_t ifnum = 0;
	cJSON_ArrayForEach(ifp, if_list)
	{
		cJSON *addr = cJSON_GetObjectItemCaseSensitive(ifp, "addr");
		if (cJSON_IsString(addr))
		{
			config->interfaces[ifnum].addr = addr->valuestring;
		}
		else
		{
			fprintf(stderr, "%s\n", "not a string");
			return;
		}

		cJSON *name = cJSON_GetObjectItemCaseSensitive(ifp, "name");
		if (cJSON_IsString(name))
		{
			config->interfaces[ifnum].name = name->valuestring;
		}

		cJSON *angle = cJSON_GetObjectItemCaseSensitive(ifp, "angle");
		if (cJSON_IsNumber(angle))
		{
			config->interfaces[ifnum].angle = angle->valueint;
		}

		// This gets filled in later
		config->interfaces[ifnum].dev_id = -1;

		config->num_interfaces = ++ifnum;
	}
}

void add_mac_filter(mac_filter_t **filters, char *str)
{
    if ((*filters) == NULL) {
        (*filters) = calloc(1,sizeof(mac_filter_t));
        (*filters)->filter = str;
        return;
    }
    mac_filter_t *p = *filters, *last = p;
    while (p != NULL) {
	    if (p->next == NULL) {
		    last = p;
        }
        p = p->next;
    }
    p = calloc(1,sizeof(mac_filter_t));
    p->filter = str;
    if (last) last->next = p;
}

hciconfig *read_config(const char *filename)
{
	FILE *fp;
	char buffer[CONFIG_BUFFER];

	if (NULL == (fp = fopen(filename, "r")))
	{
		return NULL;
	}

	fseek(fp, 0L, SEEK_END);
	long sz = ftell(fp);
	if (sz >= CONFIG_BUFFER)
	{
		fclose(fp);
		fprintf(stderr, "Config file too large.");
		return NULL;
	}
	rewind(fp);

	memset(buffer, '\0', sizeof(buffer));
	fread(buffer, 1, sz, fp);
	fclose(fp);

	cJSON *json = cJSON_Parse(buffer);
	if (!json)
		return NULL;

	hciconfig *config = calloc(1, sizeof(hciconfig));
	if (!config)
	{
		return NULL;
	}
    
	cJSON *mac_filter = cJSON_GetObjectItemCaseSensitive(json, "mac_filter");
	if (cJSON_IsString(mac_filter) && (mac_filter->valuestring != NULL))
	{
		add_mac_filter(&config->mac_filters, mac_filter->valuestring);
	} else if (cJSON_IsArray(mac_filter)) {
        cJSON *mac;
        cJSON_ArrayForEach(mac, mac_filter) {
            if (cJSON_IsString(mac) && (mac->valuestring != NULL)) {
		        add_mac_filter(&config->mac_filters, mac->valuestring);
                printf("Adding: %s\n", mac->valuestring);
            }
        }
    }

	cJSON *if_desc = cJSON_GetObjectItemCaseSensitive(json, "interfaces");
	if (!cJSON_IsArray(if_desc))
	{
		fprintf(stderr, "Not an array");
		return NULL;
	}
	load_interfaces_from_json(config, if_desc);

	if (config->num_interfaces == 0)
	{
		fprintf(stderr, "No interfaces defined");
	}

	return config;
}

void set_config_dev_id(hciconfig *config, char *addr, int dev_id)
{
	for (int i = 0; i < config->num_interfaces; i++)
	{
        if (config_verbose)
        {
                printf("Trying dev_id %d (%s) in position %d %s\n", dev_id, addr, i, config->interfaces[i].addr);
        }
		if (strcmp(config->interfaces[i].addr, addr) == 0)
		{
			config->interfaces[i].dev_id = dev_id;
            if (config_verbose)
            {
                printf("Registered dev_id %d (%s) in position %d\n", dev_id, addr, i);
            }
			return;
		}
	}
}

int map_dev_ids(hciconfig *config)
{
	struct hci_dev_list_req *dl;
	struct hci_dev_req *dr;
	struct hci_dev_info di;
	int ctl;

	if ((ctl = hci_open_socket()) < 0)
	{
		exit(1);
	}

	if (!(dl = calloc(HCI_MAX_DEV, sizeof(struct hci_dev_req) +
									   sizeof(uint16_t))))
	{
		perror("Can't allocate memory");
		return -1;
	}

	if (hci_get_devices(ctl, dl) < 0)
	{
		fprintf(stderr, "Can't get device list");
		return -1;
	}

	dr = dl->dev_req;

	char addr[18];

	for (int i = 0; i < dl->dev_num; i++)
	{
		di.dev_id = (dr + i)->dev_id;
		if (ioctl(ctl, HCIGETDEVINFO, (void *)&di) < 0)
		{
			perror("hci_get_device_info");
			continue;
		}
		ba2str(&di.bdaddr, addr);
		set_config_dev_id(config, addr, i);
	}
	close(ctl);
}

void start_scanners(hciconfig *config)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = 0;
	sa.sa_handler = sigint_handler;
	sigaction(SIGINT, &sa, NULL);

	for (int i = 0; i < config->num_interfaces; i++)
	{
		if (config->interfaces[i].dev_id == -1)
		{
            if (config_verbose)
            {
                printf("Ignoring dev_id %d (%d)\n", config->interfaces[i].dev_id, i);
            }
			continue;
		}
		if (fork() == 0)
		{
			syslog(LOG_INFO, "Scanning on device %d", config->interfaces[i].dev_id);
			lescan(&(config->interfaces[i]), config->mac_filters);
            if (config_verbose)
            {
		        syslog(LOG_INFO, "Scanner exiting");
                printf("Scanner exiting...\n");
            }
			return;
		}
    }

	int wstatus;
	pid_t w;
	while (signal_received != SIGINT && (w = wait(&wstatus)) > 0)
	{
		syslog(LOG_INFO, "Child died %d", w);
	}
    if (config_verbose)
    {
        printf("Scanner exiting...\n");
    }
	syslog(LOG_INFO, "Exiting");
}

int main(int argc, char *argv[])
{
	int opt, i, dev_id = -1;
	bdaddr_t ba;
	hciconfig *hci_config = NULL;

	while ((opt = getopt_long(argc, argv, "hc:vd", main_options, NULL)) != -1)
	{
		switch (opt)
		{
		case 'c':
			if (NULL == (hci_config = read_config(optarg)))
			{
				fprintf(stderr, ("Invalid config\n"));
			}
			break;
		case 'd':
            config_daemon = true;
            break;
		case 'v':
			config_verbose++;
			break;
		case 'h':
		default:
			usage();
			exit(0);
		}
	}

	if (!hci_config)
	{
        usage();
		exit(1);
	}

    if (config_daemon)
    {
        daemon(0, 0);
    }

	openlog(NULL, LOG_PID, LOG_USER);

	if (map_dev_ids(hci_config) < 0)
	{
		printf("Mapping failed");
		exit(2);
	}

	start_scanners(hci_config);

	return 0;
}
