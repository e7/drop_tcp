// Macros used to mark up functions e.g., __init __exit
#include <linux/init.h>
// Core header for loading LKMs into the kernel
#include <linux/module.h>
// Contains types, macros, functions for the kernel
#include <linux/kernel.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>


// The license type -- this affects runtime behavior
MODULE_LICENSE("GPL");
// The author -- visible when you use modinfo
MODULE_AUTHOR("hust");
// The description -- see modinfo
MODULE_DESCRIPTION("A simple Linux driver.");
// The version of the module
MODULE_VERSION("0.1");


// An example LKM argument -- default value is "world"
static char *name = "world";

//struct holding set of hook function options
static struct nf_hook_ops nfho;

// Param desc. charp = char ptr, S_IRUGO can be read/not changed
module_param(name, charp, S_IRUGO);
// parameter description
MODULE_PARM_DESC(name, "The name to display in /var/log/kern.log");


static unsigned int hook_func(
    const struct nf_hook_ops *ops, struct sk_buff *skb,
    const struct net_device *in, const struct net_device *out,
    int (*okfn)(struct sk_buff *))
{
    return NF_DROP;
}


/** @brief The LKM initialization function
 *  The static keyword restricts the visibility of the function to with-in
 *  this C file. The __init macro means that for a built-in driver (not a LKM)
 *  the function is only used at initialization
 *  time and that it can be discarded and its memory freed up after that point.
 *  @return returns 0 if successful
 */
static int __init drop_init(void)
{
    //printk(KERN_INFO "EBB: Hello %s from the hello LKM!\n", name);

    nfho.hook = hook_func; // function to call when conditions below met

    nfho.hooknum = NF_INET_PRE_ROUTING; // first hook in Netfilter
    nfho.pf = PF_INET; //IPV4 packets
    nfho.priority = NF_IP_PRI_FIRST;  // set to highest priority over
                                      // all other hook functions

    nf_register_hook(&nfho);

   return 0;
}


/** @brief The LKM cleanup function
 *  Similar to the initialization function, it is static.
 *  The __exit macro notifies that if this
 *  code is used for a built-in driver (not a LKM) that this func-
 *  tion is not required.
 */
static void __exit drop_exit(void)
{
    //printk(KERN_INFO "EBB: Goodbye %s from the hello LKM!\n", name);

    return;
}


/** @brief A module must use the module_init() module_exit() macros from lin
 *  ux/init.h, which identify the initialization function at insertion time
 *  and the cleanup function (as
 *  listed above)
 */
module_init(drop_init);
module_exit(drop_exit);
