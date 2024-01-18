#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/init.h> 
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/cdev.h> 
#include <linux/device.h>
#include <linux/types.h>

#include <linux/netfilter_ipv4.h>
#include <linux/netfilter.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <linux/fcntl.h>
#include <linux/delay.h>
#include <linux/syscalls.h>

#include <linux/miscdevice.h>
#include <linux/stat.h>

#include <linux/string.h>
#include <linux/timekeeping.h>


#include "core_module.h"


#define MODULE_DMESG_PREFIX ">>>--------> "

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gurova N.A.");


struct module_stats module_stats;

size_t next_free_snapshot_ind = 0;
struct traffic_snapshot *traffic_snapshot_arr;

size_t find_target_snapshot(uint64_t cur_time, uint32_t ip_v4_addr)
{
    // return ind of target snapshot in traffic_snapshot_arr if exists else SNAPSHOW_BUFFER_LENGTH
    for (size_t i = 0; i < next_free_snapshot_ind; i++) {
        if (traffic_snapshot_arr[i].ip_v4_addr == ip_v4_addr && cur_time - traffic_snapshot_arr[i].timestamp < SECOND_GRANULARITY) {
            return i;
        }
    }

    return next_free_snapshot_ind;
}

void add_traffic_info(uint32_t ip_v4_addr, uint32_t size) 
{
    uint64_t cur_time = ktime_get_seconds();

    size_t snapshot_ind = find_target_snapshot(cur_time, ip_v4_addr);

    if (snapshot_ind == SNAPSHOW_BUFFER_LENGTH) {
        printk(MODULE_DMESG_PREFIX "[WARNING] buffer overloaded");
        return;
    }

    if (snapshot_ind == next_free_snapshot_ind) {
        traffic_snapshot_arr[snapshot_ind].timestamp = cur_time;
        traffic_snapshot_arr[snapshot_ind].ip_v4_addr = ip_v4_addr;
        traffic_snapshot_arr[snapshot_ind].traffic_length = 0;
        traffic_snapshot_arr[snapshot_ind].traffic_size = 0;

        next_free_snapshot_ind += 1;

        printk(MODULE_DMESG_PREFIX "[DEBUG] new snapshot added");
    }

    traffic_snapshot_arr[snapshot_ind].traffic_length += 1;
    traffic_snapshot_arr[snapshot_ind].traffic_size += size;

    printk(MODULE_DMESG_PREFIX "[DEBUG] snapshot was updated");
}


static unsigned int catch_traffic(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;  /* An IPv4 packet header */
    uint32_t saddr;
    uint32_t tot_len;

    if (!skb) return NF_ACCEPT;

    iph = (struct iphdr *)skb_network_header(skb);
    if (iph == NULL) return NF_ACCEPT;

    saddr = iph->saddr;
    tot_len = iph->tot_len;

    add_traffic_info(saddr, tot_len);

    return NF_ACCEPT;
}

static struct nf_hook_ops module_hook_ops = 
{
    .hook = catch_traffic,
    .pf = PF_INET,
    .hooknum = NF_INET_LOCAL_IN,
    .priority = NF_IP_PRI_FIRST
};

struct list_head *module_prev;
int flag_hidden = 0;

void hide(void) {
    if (flag_hidden)
        return;

    module_prev = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    flag_hidden = 1;

    printk("module was hidden");
}

void unhide(void) {
    if (!flag_hidden)
        return;

    list_add(&THIS_MODULE->list, module_prev);
    flag_hidden = 0;

    printk("module was exposed");
}

ssize_t write_stub(struct file *filp, const char __user *buff, size_t count, loff_t *f_pos) { return 0; }
ssize_t read_stub(struct file *filp, char __user *buff, size_t count, loff_t *f_pos) { return 0; }
int open_stub(struct inode *inode, struct file *file) { return 0; }
int release_stub(struct inode *inode, struct file *file) { return 0; }

static struct file_operations module_device_fops = {
    .owner = THIS_MODULE,
    .read = read_stub,
    .write = write_stub,
    .open = open_stub,
    .release = release_stub,
};

struct miscdevice module_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = MODULE_DEVICE_NAME,
    .fops = &module_device_fops,
    .mode = S_IRWXU | S_IWGRP | S_IWOTH | S_IROTH,
};

static int __init my_module_init(void) {
    int rc = 0;

    nf_register_net_hook(&init_net, &module_hook_ops);

    rc = misc_register(&module_device);
    if (rc)
    {
        printk(MODULE_DMESG_PREFIX "[ERROR] registration was failed");
        return rc;
    }

    traffic_snapshot_arr = (struct traffic_snapshot *)kmalloc(sizeof(struct traffic_snapshot), SNAPSHOW_BUFFER_LENGTH);
    if (traffic_snapshot_arr == NULL)
    {
        printk(MODULE_DMESG_PREFIX "kmalloc error");
        return -EFAULT;
    }

    module_stats.is_buffer_overloaded = 0;
    module_stats.is_analizer_running = 0;
    module_stats.output = SHOW_MODE_UNDEFINED;
    module_stats.time_start = ktime_get_seconds();

    printk(MODULE_DMESG_PREFIX "module was loaded");

    return 0;
}

static void __exit my_module_exit(void) {

    nf_unregister_net_hook(&init_net, &module_hook_ops);

    misc_deregister(&module_device);

    kfree(traffic_snapshot_arr);

    printk(MODULE_DMESG_PREFIX "module was unloaded\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

