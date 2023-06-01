#include <stdio.h>
#include <error.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/uio.h>
#include <syslog.h>
#include "bluetooth.h"
#include "hci.h"
#include "hci_lib.h"
#include "bluetooth/l2cap.h"

#define ATT_CID                 4
#define LE_LINK     0x80

#define FLAGS_AD_TYPE 0x01
#define FLAGS_LIMITED_MODE_BIT 0x01
#define FLAGS_GENERAL_MODE_BIT 0x02

#define EIR_FLAGS                   0x01  /* flags */
#define EIR_UUID16_SOME             0x02  /* 16-bit UUID, more available */
#define EIR_UUID16_ALL              0x03  /* 16-bit UUID, all listed */
#define EIR_UUID32_SOME             0x04  /* 32-bit UUID, more available */
#define EIR_UUID32_ALL              0x05  /* 32-bit UUID, all listed */
#define EIR_UUID128_SOME            0x06  /* 128-bit UUID, more available */
#define EIR_UUID128_ALL             0x07  /* 128-bit UUID, all listed */
#define EIR_NAME_SHORT              0x08  /* shortened local name */
#define EIR_NAME_COMPLETE           0x09  /* complete local name */
#define EIR_TX_POWER                0x0A  /* transmit power level */
#define EIR_DEVICE_ID               0x10  /* device ID */

#define BUFFER_SIZE 4


/**
    02 10 00 1B 00 17 00 04 00 12 1A 00 78 5D 46 B7 BF 00 0A 90 9B 11 BE FC F2 E9 00 40 07 FD 93 E7
    02 - HCI ACL Data packet ([Vol 4] Part E, Section 5.4.2)
    10 00 - 0x0010 - Handle 16, empty flags
    1B 00 - 0x001B - Data length = 27 bytes
    17 00 - 0x0017 - lL2CAP PDU Length = 23 bytes (Section 3-A/3.1)
    04 00 - 0x0004 - CID = 4 = ATT
    12 - Attribute opcode = 0x12 - ATT_WRITE_REQ ([Vol 3] Part F, Section 3.4.5.1)
    1A 00 - 0x001A - Attribute Handle
    78..E7 - Attribute value - 20 bytes of data
*/
int hci_send_acl(int hci_socket, uint16_t hci_handle, uint16_t *data, uint16_t
                 data_length)
{
    // [Vol 4] Part E, Section 5.4.2)
    uint8_t type = HCI_ACLDATA_PKT;
    uint16_t BCflag = 0x0000;               // Broadcast flag
    uint16_t PBflag = 0x0002;               // Packet Boundary flag
    uint16_t flags = ((BCflag << 2) | PBflag) & 0x000F;
    hci_acl_hdr hd;
    hd.handle = htobs(acl_handle_pack(hci_handle, flags));
    hd.dlen = (data_length);
    struct iovec iv[3];
    int ivn = 3;
    iv[0].iov_base = &type;
    iv[0].iov_len = 1;
    iv[1].iov_base = &hd;
    iv[1].iov_len = HCI_ACL_HDR_SIZE;
    iv[2].iov_base = data;
    iv[2].iov_len = (data_length);
    // Type of operation
    // Size of ACL operation flag
    // Handle info + flags
    // L2CAP header length + data
    // L2CAP header + data
    // L2CAP header length + data
    while (writev(hci_socket, iv, ivn) < 0) {
        if (errno == EAGAIN || errno == EINTR) {
            continue;
        }
        return -1;
    }
    return 0;
}



int hci_send_l2cap(int hci_socket, uint16_t hci_handle)
{
    uint16_t buffer[BUFFER_SIZE];
    uint16_t data_length = (sizeof(uint16_t) * BUFFER_SIZE) - 1;
    uint16_t *data;
    // Section 3-A/3.1
    buffer[0] = htobs(0x0003);  // Length
    buffer[1] = htobs(0x0004);  // CID
    buffer[2] = htobs(0x0502);  // Request
    buffer[3] = htobs(0x0002);  // Request
    data = buffer;
    hci_send_acl(hci_socket, hci_handle, data, data_length);
}





static volatile int signal_received = 0;
static void cmd_lecc(int dd, char *addr)
{
    int err, opt;
    bdaddr_t bdaddr;
    uint16_t interval, latency, max_ce_length, max_interval, min_ce_length;
    uint16_t min_interval, supervision_timeout, window, handle;
    uint8_t initiator_filter, own_bdaddr_type, peer_bdaddr_type;

    own_bdaddr_type = LE_PUBLIC_ADDRESS;
    peer_bdaddr_type = LE_PUBLIC_ADDRESS;
    initiator_filter = 0; /* Use peer address */

    memset(&bdaddr, 0, sizeof(bdaddr_t));
    str2ba(addr, &bdaddr);

    //interval = htobs(0x0004);
    interval = htobs(0x0400);
    //window = htobs(0x0004);
    window = htobs(0x0400);
    min_interval = htobs(0x000F);
    //max_interval = htobs(0x000F);
    max_interval = htobs(0x0C80);
    latency = htobs(0x0000);
    supervision_timeout = htobs(0x0C80);
    min_ce_length = htobs(0x0001);
    max_ce_length = htobs(0x0001);

    err = hci_le_extended_create_connection(dd, &bdaddr, &handle);
    if (err < 0) {
        perror("Could not create connection");
        exit(1);
    }
    struct hci_version version;

    printf("Connection handle %d\n", handle);

    hci_send_l2cap(dd, handle);

    sleep(60);
    hci_close_dev(dd);
    return;


    //do_l2c_conn();
    hci_close_dev(dd);
    return;

    if (hci_read_remote_version(dd, handle, &version, 20000) == 0) {
        char *ver = lmp_vertostr(version.lmp_ver);
        printf("\tLMP Version: %s (0x%x) LMP Subversion: 0x%x\n"
               "\tManufacturer: %s (%d)\n",
               ver ? ver : "n/a",
               version.lmp_ver,
               version.lmp_subver,
               bt_compidtostr(version.manufacturer),
               version.manufacturer);
        if (ver) {
            bt_free(ver);
        }
    }
    uint8_t features[8];
    memset(features, 0, sizeof(features));
    hci_le_read_remote_features(dd, handle, features, 20000);
    printf("\tFeatures: 0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x "
           "0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x\n",
           features[0], features[1], features[2], features[3],
           features[4], features[5], features[6], features[7]);

    return;
    hci_send_l2cap(dd, handle);

    sleep(30);

    //usleep(10000);
    //hci_disconnect(dd, handle, HCI_OE_USER_ENDED_CONNECTION, 10000);
    hci_disconnect(dd, handle, HCI_REJECTED_PERSONAL, 10000);



    //hci_close_dev(dd);
}

static int read_flags(uint8_t *flags, const uint8_t *data, size_t size)
{
    size_t offset;

    if (!flags || !data) {
        return -EINVAL;
    }

    offset = 0;
    while (offset < size) {
        uint8_t len = data[offset];
        uint8_t type;

        /* Check if it is the end of the significant part */
        if (len == 0) {
            break;
        }

        if (len + offset > size) {
            break;
        }

        type = data[offset + 1];

        if (type == FLAGS_AD_TYPE) {
            *flags = data[offset + 2];
            return 0;
        }

        offset += 1 + len;
    }

    return -ENOENT;
}

static int check_report_filter(uint8_t procedure, le_advertising_info *info)
{
    uint8_t flags;

    /* If no discovery procedure is set, all reports are treat as valid */
    if (procedure == 0) {
        return 1;
    }

    /* Read flags AD type value from the advertising report if it exists */
    if (read_flags(&flags, info->data, info->length)) {
        return 0;
    }

    switch (procedure) {
    case 'l': /* Limited Discovery Procedure */
        if (flags & FLAGS_LIMITED_MODE_BIT) {
            return 1;
        }
        break;
    case 'g': /* General Discovery Procedure */
        if (flags & (FLAGS_LIMITED_MODE_BIT | FLAGS_GENERAL_MODE_BIT)) {
            return 1;
        }
        break;
    default:
        fprintf(stderr, "Unknown discovery procedure\n");
    }

    return 0;
}


static void eir_parse_name(uint8_t *eir, size_t eir_len,
                           char *buf, size_t buf_len)
{
    size_t offset;

    offset = 0;
    while (offset < eir_len) {
        uint8_t field_len = eir[0];
        size_t name_len;

        /* Check for the end of EIR */
        if (field_len == 0) {
            break;
        }

        if (offset + field_len > eir_len) {
            goto failed;
        }

        switch (eir[1]) {
        case EIR_NAME_SHORT:
        case EIR_NAME_COMPLETE:
            name_len = field_len - 1;
            if (name_len > buf_len) {
                goto failed;
            }

            memcpy(buf, &eir[2], name_len);
            return;
        }

        offset += field_len + 1;
        eir += field_len + 1;
    }

failed:
    snprintf(buf, buf_len, "(unknown)");
}


static void sigint_handler(int sig)
{
    signal_received = sig;
}

static int print_advertising_devices(int dd, uint8_t filter_type)
{
    unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
    struct hci_filter nf, of;
    struct sigaction sa;
    socklen_t olen;
    int len;

    olen = sizeof(of);
    if (getsockopt(dd, SOL_HCI, HCI_FILTER, &of, &olen) < 0) {
        printf("Could not get socket options\n");
        return -1;
    }

    hci_filter_clear(&nf);
    hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
    hci_filter_set_event(EVT_LE_META_EVENT, &nf);

    if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
        printf("Could not set socket options\n");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_NOCLDSTOP;
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, NULL);

    while (1) {
        evt_le_meta_event *meta;
        le_advertising_info *info;
        char addr[18];

        while ((len = read(dd, buf, sizeof(buf))) < 0) {
            if (errno == EINTR && signal_received == SIGINT) {
                len = 0;
                goto done;
            }

            if (errno == EAGAIN || errno == EINTR) {
                continue;
            }
            goto done;
        }

        ptr = buf + (1 + HCI_EVENT_HDR_SIZE);
        len -= (1 + HCI_EVENT_HDR_SIZE);

        meta = (void *) ptr;
        if (meta->subevent != 0x02) {
            goto done;
        }

        /* Ignoring multiple reports */
        info = (le_advertising_info *) (meta->data + 1);
        if (check_report_filter(filter_type, info)) {
            ba2str(&info->bdaddr, addr);
            printf("%s\n", addr);
            if (strncasecmp("2C:C4:07:11:24:35", addr, 17) == 0) {
                printf("Found\n");
                goto done;
            }
        }
    }

done:
    setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));

    if (len < 0) {
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int device = 1;

    int err, opt;
    uint8_t own_type = LE_PUBLIC_ADDRESS;
    uint8_t scan_type = 0x01;
    uint8_t filter_type = 0;
    uint8_t filter_policy = 0x00;
    uint16_t interval = htobs(0x0010);
    uint16_t window = htobs(0x0010);
    uint8_t filter_dup = 0x01;

    int dd = hci_open_dev(device);
    if (dd < 0) {
        perror("Could not open device");
        exit(1);
    }
    err = hci_le_set_scan_parameters(dd, scan_type, interval, window,
    own_type, filter_policy, 10000);
    if (err < 0) {
       perror("Set scan parameters failed");
       exit(1);
    }

       err = hci_le_set_scan_enable(dd, 0x01, filter_dup, 10000);
       if (err < 0) {
       perror("Enable scan failed");
       exit(1);
       }

       printf("Scanning...\n");

       err = print_advertising_devices(dd, filter_type);
       if (err < 0) {
       perror("Could not receive advertising events");
       exit(1);
       }

       err = hci_le_set_scan_enable(dd, 0x00, filter_dup, 10000);
       if (err < 0) {
       perror("Disable scan failed");
       exit(1);
       }
       err = hci_le_set_scan_enable(dd, 0x00, filter_dup, 10000);
       if (err < 0) {
       perror("Disable scan failed");
       exit(1);
       }

    hci_close_dev(dd);

}
