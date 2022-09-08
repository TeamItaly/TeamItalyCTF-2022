// SPDX-License-Identifier: GPL-2.0-only
#include <linux/init.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/refcount.h>
#include <linux/random.h>	/* for get_random_bytes() */
#include <linux/device.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/pagemap.h>
#include <linux/bio.h>
#include <linux/wait.h>
#include <linux/fs.h>
#include <asm/uaccess.h>

/* Module info constants */
#define KREAP_MODULE_NAME "kreap"
#define KREAP_CHRDEV_NAME KREAP_MODULE_NAME "ctl"
#define KREAP_BLKDEV_NAME KREAP_MODULE_NAME "mem"
#define KREAP_CHRDEV_MAJOR 69
#define KREAP_BLKDEV_MAJOR 420

/* Memory settings constants */
#define KREAP_MAX_PROCESSES (1 << MINORBITS)
#define KREAP_SECTOR_SIZE 512	/* in bytes */
/*
 * When allocating megasector we allocate 2**N pages containing both the data and the metadata.
 * If we allocate 2**9 = 512 pages (~2MB) we obtain:
 * (512 * PAGE_SIZE) % sizeof(struct treap) = 32
 * that 32 bytes will be used to keep megasector metadata (such as the refcount).
 */
#define KREAP_MS_PAGES_SHIFT 9ULL
#define KREAP_MS_PAGES_COUNT (1ULL << KREAP_MS_PAGES_SHIFT)
#define KREAP_MS_SIZE (KREAP_MS_PAGES_COUNT * PAGE_SIZE)
#define KREAP_MS_MASK (~(KREAP_MS_SIZE - 1))
#define KREAP_MS_NODES_COUNT (KREAP_MS_PAGES_COUNT * PAGE_SIZE / sizeof(struct treap))

/* Print macros */
#define kreap_err(fmt, ...) \
	printk(KERN_ERR "kreap: " fmt, ##__VA_ARGS__)
#define kreap_info(fmt, ...) \
	printk(KERN_INFO "kreap: " fmt, ##__VA_ARGS__)

/* Utility macros */
#define ceil_div(x, y) (((x) + (y) - 1) / (y))

/* Define the treap structure */
struct treap {
	u8		data[KREAP_SECTOR_SIZE];
	u32		idx;			/* absolute index of this node */
	u32		lazy;			/* lazy flag to fix the indexes */
	u64		priority;		/* priority of the root */

	/* left and right subtrees */
	struct treap	*l;
	struct treap	*r;
} __randomize_layout;
typedef struct treap *treap_ptr;

/* This structure will be used to allocate more memory for treaps */
struct kreap_megasector {
	/* Padding to align the megasector to a multiple of PAGE_SIZE */
	u8		padding[PAGE_SIZE - ((sizeof(refcount_t) + sizeof(struct treap)
				* KREAP_MS_NODES_COUNT) & (PAGE_SIZE - 1))];

	refcount_t	refcount;			/* Reference count used to free megasectors */
	struct treap	nodes[KREAP_MS_NODES_COUNT];	/* Treap nodes */
} __randomize_layout;

/* Define command formats */
enum cmds {
	CMD_GET_DISK = 0,
	CMD_MALLOC,
	CMD_FREE,
};
struct kreap_cmd {
	enum cmds	id;
	u32		arg0;
	u32		arg1;
};
enum kreap_cmd_states {
	CMD_STATE_IDLE = 0,
	CMD_STATE_READY,
	CMD_STATE_RUNNING,
};
struct kreap_ans {
	int		err;	/* reuse errno errors */
	u32		arg0;
};

/* Data exclusive to a process using the kreap module */
struct kreap_pdata {
	/* used in kreapctl.c */
	struct kreap_cmd	cmd;		/* last command issued to the ctl device */
	struct kreap_ans	ans;		/* last answer calculated by the ctl device */
	bool			ready;		/* the ctl device is ready to answer */
	wait_queue_head_t	wait_queue;	/* wait queue for the ctl device to answer */
	/* used in kreapmem.c */
	struct gendisk		*disk;		/* disk device */
	treap_ptr		treap;		/* the treap */
	u32			next_sector;	/* the next sector that will be allocated */
	u32			free_sectors;	/* the number of free sectors */

	/* used to create a node in /dev */
	struct device		*device;
} __randomize_layout;

/* Treap functions */

/*
 * treap_push - Push a node's lazy index to the children
 */
static void treap_push(treap_ptr treap)
{
	if (!treap)
		return;

	treap->idx += treap->lazy;
	if (treap->l)
		treap->l->lazy += treap->lazy;
	if (treap->r)
		treap->r->lazy += treap->lazy;
	treap->lazy = 0;
}

/*
 * treap_get_last_idx - Get the last index of a treap
 */
static u32 treap_get_last_idx(treap_ptr treap)
{
	if (!treap)
		return 0;

	treap_push(treap);
	return treap->r ? treap_get_last_idx(treap->r) : treap->idx + 1;
}

/*
 * treap_find_by_idx - Get a pointer to a node of a treap having index `idx`
 */
static treap_ptr treap_find_by_idx(treap_ptr treap, u32 idx)
{
	if (!treap)
		return ERR_PTR(-EFAULT);

	treap_push(treap);

	/* the element we're searching for is the root */
	if (idx == treap->idx)
		return treap;
	/* the element we're searching for is in the left subtree */
	else if (idx < treap->idx) {
		if (treap->l)
			return treap_find_by_idx(treap->l, idx);
		else
			return treap;
	}
	/* the element we're searching for is in the right subtree */
	else {
		if (treap->r)
			return treap_find_by_idx(treap->r, idx);
		else
			return treap;
	}
}

/*
 * treap_data_by_idx - Get a pointer to the data of a treap node having index `idx`
 */
static void *treap_data_by_idx(treap_ptr treap, u32 idx)
{
	treap_ptr node = treap_find_by_idx(treap, idx);

	if (IS_ERR(node))
		return node;
	return (void *)node->data;
}

/*
 * treap_split - Split a treap into two treaps (does not update indexes)
 */
static void treap_split(treap_ptr root, treap_ptr *first, treap_ptr *second, u32 idx)
{
	if (root == NULL) {
		*first = *second = NULL;
		return;
	}

	treap_push(root);

	if (idx <= root->idx) {
		/* the root goes to the right */
		*second = root;
		treap_split(root->l, first, &(*second)->l, idx);
	} else {
		/* the root goes to the left */
		*first = root;
		treap_split(root->r, &(*first)->r, second, idx);
	}
}

/*
 * treap_split_upd - Split a treap into two treaps (updates indexes)
 */
static void treap_split_upd(treap_ptr root, treap_ptr *first, treap_ptr *second, u32 idx)
{
	treap_split(root, first, second, idx);
	if (*second)
		(*second)->lazy -= idx;
}

/*
 * treap_merge - Merge two treaps into a single one (does not update indexes)
 */
static treap_ptr treap_merge(treap_ptr first, treap_ptr second)
{
	treap_ptr root;

	treap_push(first);
	treap_push(second);

	if (first == NULL || second == NULL)
		return first ? first : second;

	/* Choose the new root according to the priority */
	if (first->priority >= second->priority) {
		root = first;
		root->r = treap_merge(first->r, second);
	} else {
		root = second;
		root->l = treap_merge(first, second->l);
	}

	return root;
}

/*
 * treap_merge_upd - Merge two treaps into a single one (updates indexes)
 */
static treap_ptr treap_merge_upd(treap_ptr first, treap_ptr second)
{
	u32 left_sz = treap_get_last_idx(first);

	if (second)
		second->lazy += left_sz;
	return treap_merge(first, second);
}

/*
 * treap_heapify - Make the priority of a treap node satisfy the heap property
 */
static void treap_heapify(treap_ptr treap)
{
	treap_ptr max;

	if (!treap)
		return;

	/* find the maximum priority */
	max = treap;
	if (treap->l && max->priority < treap->l->priority)
		max = treap->l;
	if (treap->r && max->priority < treap->r->priority)
		max = treap->r;

	/* not heapified */
	if (treap != max) {
		swap(treap->priority, max->priority);
		return treap_heapify(max); // descend on the treap
	}
}

/*
 * treap_build - Build an empty treap of sz nodes in the area pointed by buf
 * O(N) (courtesy of cp-algorithms.com)
 */
static treap_ptr treap_build(treap_ptr buf, u32 sz, u32 idx)
{
	u32 mid;

	if (sz == 0)
		return NULL;
	mid = sz / 2;

	/* Setup the middle node */
	buf[mid].idx = idx + mid;
	buf[mid].lazy = 0;
	get_random_bytes(&buf[mid].priority, sizeof(u64));
	buf[mid].l = treap_build(buf, mid, idx);
	buf[mid].r = treap_build(buf + (mid + 1), sz - mid - 1, idx + mid + 1);

	treap_heapify(&buf[mid]);

	return &buf[mid];
}

/* Devices functions */
static struct class *kreap_class;
static struct kreap_pdata kreap_pdata_arr[KREAP_MAX_PROCESSES];

/* kreapmem stuff */

/*
 * Functions to read and write to the kreap, inspired by the brd driver.
 */
static int copy_to_kreapmem(struct kreap_pdata *pdata, const void *src,
			sector_t sector, size_t len)
{
	/* Check if the sector number is valid */
	if (len > U32_MAX)
		return -EINVAL;

	while (len) {
		/* Get the sector */
		void *dst = treap_data_by_idx(pdata->treap, (u32)sector);

		if (IS_ERR_OR_NULL(dst)) {
			kreap_err("sector %lld not found\n", sector);
			return -EIO;
		}

		/* Copy the data */
		memcpy(dst, src, min_t(size_t, len, KREAP_SECTOR_SIZE));

		src += min_t(size_t, len, KREAP_SECTOR_SIZE);
		len -= min_t(size_t, len, KREAP_SECTOR_SIZE);
		sector++;
	}

	return 0;
}

static int copy_from_kreapmem(void *dst, struct kreap_pdata *pdata,
			sector_t sector, size_t len)
{
	/* Check if the sector number is valid */
	if (len > U32_MAX)
		return -EINVAL;

	while (len) {
		/* Get the sector */
		void *src = treap_data_by_idx(pdata->treap, (u32)sector);

		if (IS_ERR_OR_NULL(src)) {
			kreap_err("sector %llu not found\n", sector);
			return -EIO;
		}

		/* Copy the data */
		memcpy(dst, src, min_t(size_t, len, KREAP_SECTOR_SIZE));
		dst += min_t(size_t, len, KREAP_SECTOR_SIZE);
		len -= min_t(size_t, len, KREAP_SECTOR_SIZE);
		sector++;
	}

	return 0;
}

static int kreapmem_do_bvec(struct kreap_pdata *pdata, struct page *page,
			unsigned int len, unsigned int off, unsigned int op,
			sector_t sector)
{
	void *addr;
	int err = 0;

	/* Map the page for temporary usage */
	addr = kmap_local_page(page);
	if (op_is_write(op)) {
		flush_dcache_page(page);
		err = copy_to_kreapmem(pdata, addr + off, sector, len);
	} else {
		err = copy_from_kreapmem(addr + off, pdata, sector, len);
		flush_dcache_page(page);
	}
	kunmap_local(addr);

	return 0;
}

static blk_qc_t kreapmem_submit_bio(struct bio *bio)
{
	struct kreap_pdata *pdata = bio->bi_bdev->bd_disk->private_data;
	struct bio_vec bvec;
	struct bvec_iter iter;

	bio_for_each_segment(bvec, bio, iter) {
		int err;

		/* Pass the current bvec parameters */
		err = kreapmem_do_bvec(pdata, bvec.bv_page, bvec.bv_len, bvec.bv_offset,
				  bio_op(bio), iter.bi_sector);
		if (err) {
			bio_io_error(bio);
			return BLK_QC_T_NONE;
		}
	}

	bio_endio(bio);
	return BLK_QC_T_NONE;
}

static int kreapmem_rw_page(struct block_device *bdev, sector_t sector,
		       struct page *page, enum req_opf op)
{
	struct kreap_pdata *pdata = bdev->bd_disk->private_data;
	int err = 0;

	if (PageTransHuge(page))
		return -ENOTSUPP;

	/* Pass the current page as a dummy bvec */
	err = kreapmem_do_bvec(pdata, page, PAGE_SIZE, 0, op, sector);
	page_endio(page, op_is_write(op), err);
	return err;
}

static const struct block_device_operations kreapmem_fops = {
	.owner		= THIS_MODULE,
	.submit_bio	= kreapmem_submit_bio,
	.rw_page	= kreapmem_rw_page,
};

/*
 * Allocates the memory needed for a new megasector.
 */
static treap_ptr kreap_alloc_megasector(void)
{
	gfp_t gfp_mask;
	struct kreap_megasector *ms;

	/*
	 * Use NOIO to avoid recursing into the filesystem.
	 * Use COMP to get a hugepage if available (a megasector is as large as a single 2MB hugepage).
	 */
	gfp_mask = GFP_NOIO | __GFP_COMP;
	ms = kmalloc(KREAP_MS_SIZE, gfp_mask);

	/* Check for errors */
	if (ms == NULL) {
		kreap_err("failed to allocate megasector\n");
		return ERR_PTR(-ENOMEM);
	}

	/* Setup the megasector */
	refcount_set(&ms->refcount, KREAP_MS_NODES_COUNT);
	return treap_build((treap_ptr)(&ms->nodes), KREAP_MS_NODES_COUNT, 0);
}

/*
 * Frees a megasector.
 */
static void kreap_free_megasector(treap_ptr treap)
{
	/* Get the megasector */
	struct kreap_megasector *ms = (struct kreap_megasector *)((unsigned long)treap & KREAP_MS_MASK);

	/* Check if the megasector is still in use */
	if (refcount_read(&ms->refcount)) {
		kreap_err("trying to free an in use megasector\n");
		return;
	}

	kfree(ms);
}

/*
 * Check if there is enough space, if not allocates megasectors until we have enough
 */
static int kreapmem_check_for_space(struct kreap_pdata *pdata, u32 req_sectors)
{
	treap_ptr ms;

	while (pdata->free_sectors < req_sectors) {
		/* Allocate a megasector */
		ms = kreap_alloc_megasector();
		if (IS_ERR_OR_NULL(ms))
			return -ENOSPC;
		/* Add the megasector to the treap */
		pdata->treap = treap_merge_upd(pdata->treap, ms);
		pdata->free_sectors += KREAP_MS_NODES_COUNT;
	}
	return 0;
}

/*
 * Recurse through the treap and free all the megasectors
 */
static void kreapmem_release_mem_recursive(treap_ptr treap)
{
	struct kreap_megasector *ms;

	if (treap == NULL)
		return;

	/* Free children */
	kreapmem_release_mem_recursive(treap->l);
	kreapmem_release_mem_recursive(treap->r);

	ms = (struct kreap_megasector *)((unsigned long)treap & KREAP_MS_MASK);

	/* Remove a reference */
	if (refcount_dec_and_test(&ms->refcount)) {
		/* Free the megasector */
		kreap_free_megasector(treap);
	}
}

/*
 * Initialize a kreap memory device
 * Does not set disk->private_data
 */
static struct gendisk *kreapmem_mkdisk(int minor)
{
	struct gendisk *disk;
	int err;

	/* Create a new gendisk */
	disk = blk_alloc_disk(NUMA_NO_NODE);
	if (!disk) {
		kreap_err("failed to allocate disk");
		return disk;
	}

	disk->major		= KREAP_BLKDEV_MAJOR;
	disk->first_minor	= minor;
	disk->minors		= 1;
	disk->fops		= &kreapmem_fops;
	/* Don't scan for partitions */
	disk->flags		= GENHD_FL_NO_PART_SCAN;
	/* Set the disk name */
	snprintf(disk->disk_name, sizeof(disk->disk_name), KREAP_BLKDEV_NAME "%d", minor);

	/* Setup the disk queue parameters */
	blk_queue_logical_block_size(disk->queue, KREAP_SECTOR_SIZE);
	blk_queue_physical_block_size(disk->queue, KREAP_SECTOR_SIZE);
	blk_queue_bounce_limit(disk->queue, BLK_BOUNCE_NONE);
	/* Not a rotational device */
	blk_queue_flag_set(QUEUE_FLAG_NONROT, disk->queue);
	/* Not contributing to randomness */
	blk_queue_flag_clear(QUEUE_FLAG_ADD_RANDOM, disk->queue);

	/* Set the disk capacity to 0, add sectors only when needed */
	set_capacity(disk, 0);

	err = add_disk(disk);
	if (err) {
		kreap_err("failed to add disk");
		blk_cleanup_disk(disk);
		return NULL;
	}

	return disk;
}

/*
 * Removes a kreap memory disk
 */
static void kreapmem_rmdisk(struct gendisk *disk)
{
	del_gendisk(disk);
	blk_cleanup_disk(disk);
}

static inline int kreapmem_init(void)
{
	int err;

	/* Register the device */
	err = register_blkdev(KREAP_BLKDEV_MAJOR, KREAP_BLKDEV_NAME);
	if (err < 0) {
		kreap_err("error registering block device\n");
		return err;
	}

	/* Don't allocate disks for now, they will be allocated on kreapctl_open */
	return 0;
}

static inline void kreapmem_exit(void)
{
	/* The partitions should already be freed by each call to kreapctl_release */
	/* Unregister the device */
	unregister_blkdev(KREAP_BLKDEV_MAJOR, KREAP_BLKDEV_NAME);
}

/* kreapctl stuff */
static int proc_cnt;
static struct kreapctl {
	struct cdev	cdev;
	struct device	*device;
} __randomize_layout kreapctl;

static int kreapctl_open(struct inode *inode, struct file *filp)
{
	int i;
	struct gendisk *disk;

	/* Iterate from proc_cnt to (proc_cnt - 1) to find a free minor */
	i = proc_cnt;
	do {
		if (kreap_pdata_arr[i++].device == NULL)
			break;
	} while (i % KREAP_MAX_PROCESSES != proc_cnt);

	if (i % KREAP_MAX_PROCESSES == proc_cnt) {
		kreap_err("no free disks\n");
		return -EBUSY;
	}
	proc_cnt = i-- % KREAP_MAX_PROCESSES;

	/* Initialize data for a new process */
	disk = kreapmem_mkdisk(i);

	if (!disk)
		return -ENOMEM;

	/* Setup disk and queue */
	kreap_pdata_arr[i].disk = disk;
	init_waitqueue_head(&kreap_pdata_arr[i].wait_queue);
	disk->private_data = &kreap_pdata_arr[i];
	filp->private_data = &kreap_pdata_arr[i];

	/* Finally, create the device entry */
	kreap_pdata_arr[i].device = device_create(kreap_class, NULL, MKDEV(KREAP_BLKDEV_MAJOR, i),
					NULL, KREAP_BLKDEV_NAME "%d", i);

	return 0;
}

static int kreapctl_release(struct inode *inode, struct file *filp)
{
	struct kreap_pdata *pdata;

	/* Make sure we don't double free */
	if (unlikely(filp->private_data == NULL)) {
		kreap_err("no partition to release\n");
		return -EINVAL;
	}

	pdata = filp->private_data;

	/* Free every partition */
	kreapmem_release_mem_recursive(pdata->treap);

	/* Destroy the device entry */
	device_destroy(kreap_class, MKDEV(KREAP_BLKDEV_MAJOR, pdata->disk->first_minor));
	pdata->device = NULL;
	/* Clear disk */
	kreapmem_rmdisk(pdata->disk);
	pdata->disk = NULL;

	filp->private_data = NULL;
	return 0;
}

static ssize_t kreapctl_read(struct file *filp, char __user *user_buf, size_t size, loff_t *offset)
{
	ssize_t cnt;
	struct kreap_pdata *pdata = filp->private_data;

	/* Wait for the process to be ready to answer */
	wait_event_interruptible(pdata->wait_queue, pdata->ready);

	/* Calculate the size to transfer */
	cnt = min_t(ssize_t, sizeof(struct kreap_ans) - *offset, size);
	if (unlikely(cnt < 0)) {
		kreap_err("could not copy to user\n");
		return -EFAULT;
	}

	if (copy_to_user(user_buf, &pdata->ans + *offset, cnt)) {
		kreap_err("failed to copy_to_user\n");
		return -EFAULT;
	}

	/* Update the offset */
	*offset += cnt;
	if (*offset == sizeof(struct kreap_ans)) {
		pdata->ready = 0;
		*offset = 0;
	}

	return cnt;
}

static ssize_t kreapctl_write(struct file *filp, const char __user *user_buf, size_t size, loff_t *offset)
{
	ssize_t cnt;
	struct kreap_pdata *pdata = filp->private_data;

	/* Set the number of bytes to receive */
	cnt = min_t(ssize_t, sizeof(struct kreap_cmd) - *offset, size);
	if (unlikely(cnt < 0)) {
		kreap_err("could not copy from user\n");
		return -EFAULT;
	}

	if (copy_from_user(&pdata->cmd + *offset, user_buf, cnt)) {
		kreap_err("failed to copy_from_user\n");
		pdata->ready = false;
		return -EFAULT;
	}

	*offset += cnt;

	/* If everything was written, execute the command and set the device as ready to answer */
	if (*offset == sizeof(struct kreap_cmd)) {
		switch (pdata->cmd.id) {
		case CMD_GET_DISK:
			pdata->ans.err = 0;
			pdata->ans.arg0 = (u32)pdata->disk->first_minor;
			break;
		case CMD_MALLOC:
			/*
			 * arg0 = number of sectors to request
			 */

			/* check if we need to allocate more megasectors */
			pdata->ans.err = kreapmem_check_for_space(pdata, pdata->cmd.arg0);

			if (pdata->ans.err == 0) {
				pdata->ans.arg0 = pdata->next_sector;
				pdata->next_sector += pdata->cmd.arg0;
				pdata->free_sectors -= pdata->cmd.arg0;
				/* add the capacity in sectors */
				set_capacity_and_notify(pdata->disk, get_capacity(pdata->disk) + pdata->cmd.arg0);
			}
			break;
		case CMD_FREE: {
			/*
			 * arg0 = offset
			 * arg1 = number of sectors to free
			 */

			/* We aren't really freeing memory here, we are just marking it as free. */
			u32 start = pdata->cmd.arg0;
			u32 end = start + pdata->cmd.arg1;
			treap_ptr left, right, mid;

			/* Quick checks on the parameters */
			if (start >= pdata->next_sector || end > pdata->next_sector) {
				pdata->ans.err = -EINVAL;
				break;
			}

			/* Split preserving indexes */
			treap_split(pdata->treap, &mid, &right, end);

			/* Split with update */
			treap_split_upd(mid, &left, &mid, start);

			/* Merge the two parts, not updating indexes */
			pdata->treap = treap_merge(left, right);

			/* Merge the other two, updating indexes */
			pdata->treap = treap_merge_upd(pdata->treap, mid);

			/* Update the free sectors */
			pdata->free_sectors += end - start;
			break;
		}
		default:
			kreap_err("unknown command %d\n", pdata->cmd.id);
			return -EINVAL;
		}

		pdata->ready = true;
		wake_up_interruptible(&pdata->wait_queue);

		/* Reset the offset */
		*offset = 0;
	}

	return cnt;
}

static const struct file_operations kreapctl_fops = {
	.owner		= THIS_MODULE,
	.open		= kreapctl_open,
	.release	= kreapctl_release,
	.read		= kreapctl_read,
	.write		= kreapctl_write
};

static inline int kreapctl_init(void)
{
	int err;

	/* Register and create the control device */
	err = register_chrdev_region(MKDEV(KREAP_CHRDEV_MAJOR, 0), 1, KREAP_CHRDEV_NAME);
	if (err < 0) {
		kreap_err("failed to register " KREAP_CHRDEV_NAME " with major %d\n", KREAP_CHRDEV_MAJOR);
		goto out;
	}
	cdev_init(&kreapctl.cdev, &kreapctl_fops);
	kreapctl.cdev.owner = THIS_MODULE;

	/* Add the device to the system */
	err = cdev_add(&kreapctl.cdev, MKDEV(KREAP_CHRDEV_MAJOR, 0), 1);
	if (err < 0) {
		kreap_err("failed to add " KREAP_CHRDEV_NAME " device\n");
		goto out_unregister;
	}

	/* Create the device */
	kreapctl.device = device_create(kreap_class, NULL, MKDEV(KREAP_CHRDEV_MAJOR, 0), NULL, KREAP_CHRDEV_NAME);
	return 0;

out_unregister:
	unregister_chrdev_region(MKDEV(KREAP_CHRDEV_MAJOR, 0), 1);
out:
	return err;
}

static inline void kreapctl_exit(void)
{
	/* Remove the device from the system */
	device_destroy(kreap_class, MKDEV(KREAP_CHRDEV_MAJOR, 0));

	/* Delete and unregister the chrdev */
	cdev_del(&kreapctl.cdev);
	unregister_chrdev_region(MKDEV(KREAP_CHRDEV_MAJOR, 0), 1);
}

/* Module info and kernel interface */
MODULE_DESCRIPTION("kreap > heap");
MODULE_AUTHOR("collodel");
MODULE_LICENSE("GPL");

static int __init kreap_init(void)
{
	int err;

	/* Initialize the kreap class */
	kreap_class = class_create(THIS_MODULE, KREAP_MODULE_NAME);
	if (IS_ERR(kreap_class)) {
		err = PTR_ERR(kreap_class);
		kreap_err("failed to initialize " KREAP_MODULE_NAME " class\n");
		return err;
	}

	err = kreapmem_init();
	if (err) {
		kreap_err("failed to initialize " KREAP_BLKDEV_NAME " device\n");
		return err;
	}

	err = kreapctl_init();
	if (err) {
		kreap_err("failed to initialize " KREAP_CHRDEV_NAME " device\n");
		kreapmem_exit();
		return err;
	}

	kreap_info("module initialized successfully!\n");
	return 0;
}

static void __exit kreap_exit(void)
{
	/* Destroy both devices */
	kreapctl_exit();
	kreapmem_exit();

	/* Destroy the kreap class */
	class_destroy(kreap_class);
	kreap_info("module removed successfully\n");
}

module_init(kreap_init);
module_exit(kreap_exit);