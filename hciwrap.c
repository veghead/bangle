#include "hciwrap.h"
#include <sys/ioctl.h>

int hci_open_socket()
{
	return socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
}

int hci_get_devices(int ctl, struct hci_dev_list_req *dl) 
{
    struct hci_dev_req *dr;
    int i;

    dl->dev_num = HCI_MAX_DEV;
    dr = dl->dev_req;

    if (ioctl(ctl, HCIGETDEVLIST, (void *) dl) < 0) {
        perror("Can't get device list");
        return -1;
    }
    return dl->dev_num;
}

int hci_get_device_info(int ctl, struct hci_dev_info *di)
{
    return ioctl(ctl, HCIGETDEVINFO, (void *) &di);
}

