/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 2006-2010 Pawel Jakub Dawidek <pjd@FreeBSD.org>
 * All rights reserved.
 *
 * Copyright (c) 2011-2012, Spectra Logic Corporation. All rights reserved.
 */

/* Portions Copyright 2010 Robert Milkowski */
/* Portions Copyright 2011 Martin Matuska <mm@FreeBSD.org> */

/*
 * On FreeBSD ZVOLs are simply GEOM providers like any other storage device
 * in the system.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/errno.h>
#include <sys/disk.h>
#include <sys/uio.h>
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/zap.h>
#include <sys/spa.h>
#include <sys/zio.h>
#include <sys/dmu_objset.h>
#include <sys/dmu_traverse.h>
#include <sys/dnode.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_prop.h>
#include <sys/dkio.h>
#include <sys/byteorder.h>
#include <sys/dirent.h>
#include <sys/policy.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_ioctl.h>
#include <sys/zil.h>
#include <sys/refcount.h>
#include <sys/zfs_znode.h>
#include <sys/zfs_rlock.h>
#include <sys/vdev_impl.h>
#include <sys/dsl_destroy.h>
#include <sys/zvol.h>
#include <sys/zvol_impl.h>
#include <sys/zil_impl.h>
#include <geom/geom.h>

#include "zfs_namecheck.h"

struct g_class zfs_zvol_class = {
	.name = "ZFS::ZVOL",
	.version = G_VERSION,
};

DECLARE_GEOM_CLASS(zfs_zvol_class, zfs_zvol);

typedef enum zvf_state {
	ZVF_STATE_SETUP,	/* Device being setup */
	ZVF_STATE_OPERATIONAL,	/* Device operational */
	ZVF_STATE_DESTROY,	/* Device being destroyed */
	ZVF_STATE_GONE,		/* Device gone */
} zvf_state_t;

typedef struct zvol_freebsd_state {
	zvol_state_t		*zv;
	zvf_state_t		zvf_state;
	struct g_provider	*zvf_provider;
	struct bio_queue_head	zvf_queue;
	struct mtx		zvf_mtx;
	struct zvol_iterate_arg	*zvf_zvi;
} zvol_freebsd_state_t;

static int zvol_get_data(void *arg, lr_write_t *lr, char *buf, zio_t *zio);
static int zvol_geom_access(struct g_provider *pp, int dcr, int dcw, int dce);
static void zvol_geom_start(struct bio *bp);
static void zvol_device_worker(void *arg);

/* The GEOM device names start with 'zvol/'. */
#define	ZVF_GEOM_NAME(pp)						\
	(&(pp)->name[sizeof(ZVOL_DRIVER)])

static zvol_freebsd_state_t *
zvol_geom_lookup(const char *name)
{
	struct g_provider *pp;
	struct g_geom *gp;
	zvol_freebsd_state_t *zvf = NULL;

	g_topology_assert();
	LIST_FOREACH(gp, &zfs_zvol_class.geom, geom) {
		pp = LIST_FIRST(&gp->provider);
		if (pp == NULL || pp->private == NULL)
			continue;
		if (strcmp(ZVF_GEOM_NAME(pp), name) == 0)
			return (pp->private);
	}
	return (NULL);
}

static void
zvol_promote_sync(dsl_dataset_promote_arg_t *ddpa, dsl_dataset_t *origin_ds,
    dsl_dataset_t *clone_ds, dsl_dataset_t *snap_ds)
{
	char *dsname;

	/*
	 * We only need to change zvol devices if we are moving a snapshot
	 * from the origin to the clone, i.e. snapshots that were created
	 * before the clone existed.  So if this snapshot belongs only to
	 * one of the two, then there is nothing to do.
	 */
	if (origin_ds == NULL || clone_ds == NULL)
		return;

	dsname = kmem_alloc(MAXNAMELEN, KM_SLEEP);

	/* Create the new device using the snap's name. */
	dsl_dataset_name(snap_ds, dsname);
	VERIFY0(zvol_create_device(dsname, ddpa->ddpa_user_data));

	/*
	 * Remove the original zvol device.  Since snap_ds no longer hangs
	 * off origin_ds, use its ds_snapname to reconstruct the name.
	 */
	dsl_dataset_name(origin_ds, dsname);
	snprintf(dsname, MAXNAMELEN, "%s@%s", dsname, snap_ds->ds_snapname);
	VERIFY0(zvol_destroy_device(dsname, ddpa->ddpa_user_data));

	kmem_free(dsname, MAXNAMELEN);
}

static void
zvol_iterate_wait_and_destroy(struct zvol_iterate_arg *zvi)
{
	zvol_iterate_wait(zvi);
	kmem_free(zvi, sizeof(*zvi));
}

static struct zvol_iterate_arg *
zvol_create_iteration(void)
{
	struct zvol_iterate_arg *zvi = kmem_alloc(sizeof(*zvi), KM_SLEEP);
	zvol_setup_iteration(zvi);
	return (zvi);
}

static void
zvol_promote_cleanup(dsl_dataset_promote_arg_t *ddpa)
{
	zvol_iterate_wait_and_destroy(ddpa->ddpa_user_data);
	ddpa->ddpa_user_data = NULL;
}

int
zvol_promote_init(dsl_dataset_promote_arg_t *ddpa)
{
#ifdef _KERNEL
	ddpa->ddpa_user_syncfunc = zvol_promote_sync;
	ddpa->ddpa_user_cleanupfunc = zvol_promote_cleanup;
	ddpa->ddpa_user_data = zvol_create_iteration();
#endif
	return (0);
}

void
zvol_size_changed(zvol_state_t *zv)
{
	zvol_freebsd_state_t *zvf;
	struct g_provider *pp = NULL;

	DROP_GIANT();
	g_topology_lock();
	zvf = zvol_geom_lookup(zv->zv_name);
	if (zvf)
		pp = zvf->zvf_provider;
	/*
	 * Changing provider size is not really supported by GEOM, but it
	 * should be safe when the provider is closed.
	 */
	if (pp)
		if (pp->acr + pp->ace + pp->acw == 0)
			pp->mediasize = zv->zv_volsize;
	g_topology_unlock();
	PICKUP_GIANT();
}

static void
zvol_geom_setstate(zvol_freebsd_state_t *zvf, zvf_state_t zvf_state)
{
	zvf->zvf_state = zvf_state;
	wakeup(&zvf->zvf_state);
}

static void
zvol_geom_gone(struct g_provider *pp)
{
	zvol_freebsd_state_t *zvf;

	g_topology_assert();
	zvf = pp->private;

	mtx_lock(&zvf->zvf_mtx);
	/* Bleed out the queue if needed; it is probably already dead. */
	while (zvf->zvf_state == ZVF_STATE_DESTROY)
		mtx_sleep(&zvf->zvf_state, &zvf->zvf_mtx, 0, "zvol:destroy", 0);
	/*
	 * Wait for a final close, if needed.  Should not wait very long, as
	 * any new I/Os get ENXIO at this stage.
	 */
	while (zvf->zv != NULL)
		mtx_sleep(&zvf->zvf_state, &zvf->zvf_mtx, 0, "zvol:gone", 0);
	mtx_destroy(&zvf->zvf_mtx);

	/* Notify anyone waiting for this zvf to go away */
	if (zvf->zvf_zvi) {
		mtx_lock(&zvf->zvf_zvi->zvi_mtx);
		zvf->zvf_zvi->zvi_cookie--;
		if (zvf->zvf_zvi->zvi_cookie == 0)
			wakeup(zvf->zvf_zvi);
		mtx_unlock(&zvf->zvf_zvi->zvi_mtx);
	}

	kmem_free(zvf, sizeof(*zvf));
}

static void
zvol_geom_destroy(zvol_freebsd_state_t *zvf, struct zvol_iterate_arg *zvi)
{

	g_topology_assert();
	if (zvi != NULL) {
		zvf->zvf_zvi = zvi;
		mtx_lock(&zvi->zvi_mtx);
		zvi->zvi_cookie++;
		mtx_unlock(&zvi->zvi_mtx);
	}

	mtx_lock(&zvf->zvf_mtx);
	zvol_geom_setstate(zvf, ZVF_STATE_DESTROY);
	wakeup_one(&zvf->zvf_queue);
	/* Don't wait.  Instead, let the gone callback complete cleanup. */
	mtx_unlock(&zvf->zvf_mtx);
	g_wither_geom(zvf->zvf_provider->geom, ENXIO);
}

/*
 * This function exists simply to obtain basic information about the zvol
 * object without needing a zvol_open/zvol_close.
 */
static int
zvol_geom_info(const char *zv_name, uint64_t *volsize)
{
	int error;
	objset_t *os;

	error = dmu_objset_hold(zv_name, FTAG, &os);
	if (error != 0)
		return (error);

	error = zap_lookup(os, ZVOL_ZAP_OBJ, "size", 8, 1, volsize);
	if (error != 0)
		*volsize = 0;
	dmu_objset_rele(os, FTAG);
	return (error);
}

void
zvol_geom_create(const char *zv_name)
{
	struct g_geom *gp;
	struct g_provider *pp;
	zvol_freebsd_state_t *zvf;

	zvf = kmem_zalloc(sizeof(*zvf), KM_SLEEP);

	gp = g_new_geomf(&zfs_zvol_class, "zfs::zvol::%s", zv_name);
	gp->start = zvol_geom_start;
	gp->access = zvol_geom_access;
	gp->providergone = zvol_geom_gone;
	pp = g_new_providerf(gp, "%s/%s", ZVOL_DRIVER, zv_name);
	pp->sectorsize = DEV_BSIZE;
	pp->private = zvf;
	zvf->zvf_provider = pp;
	bioq_init(&zvf->zvf_queue);
	mtx_init(&zvf->zvf_mtx, "zvol", NULL, MTX_DEF);
	zvf->zvf_state = ZVF_STATE_SETUP;
	g_error_provider(pp, 0);
	kproc_kthread_add(zvol_device_worker, zvf, &zfsproc, NULL,
	    0, 0, "zfskern", "zvol %s", ZVF_GEOM_NAME(pp));
}

/*
 * SPECNAMELEN is cdev.__si_namebuf's size; minus driver name, minus 1 for
 * the slash after the driver name, minus 1 for nul byte.
 */
#define MAXZVOLNAMELEN	SPECNAMELEN - sizeof(ZVOL_DRIVER) - 2
int
zvol_namecheck(const char *name)
{

	if (strlen(name) > MAXZVOLNAMELEN)
		return (ENAMETOOLONG);
	return (0);
}

int
zvol_create_device(const char *zv_name, void *arg __unused)
{
	int error;

	ZFS_LOG(1, "Creating ZVOL %s...", zv_name);

	DROP_GIANT();
	g_topology_lock();
	error = (zvol_geom_lookup(zv_name) != NULL) ? EEXIST : 0;
	if (error == 0)
		zvol_geom_create(zv_name);
	g_topology_unlock();
	PICKUP_GIANT();
	return (error);
}

int
zvol_destroy_device(const char *zv_name, void *arg)
{
	zvol_freebsd_state_t *zvf;
	struct zvol_iterate_arg *zvi = (struct zvol_iterate_arg *)arg;
	int error;

	ASSERT(zvi != NULL);
	ZFS_LOG(1, "Destroying ZVOL %s...", zv_name);
	DROP_GIANT();
	g_topology_lock();

	zvf = zvol_geom_lookup(zv_name);
	error = (zvf != NULL) ? 0 : ENXIO;
	if (zvf)
		zvol_geom_destroy(zvf, zvi);
	g_topology_unlock();
	PICKUP_GIANT();
	return (error);
}

/************************************************************************
 * XXX This is a hack.  Its purpose is to allow us to wait for the zvol's
 *     device node to appear.  But we should be using a notification
 *     mechanism instead!  Preferably one that allows us to wait for an
 *     entire set to be completed.
 *
 *     Note that we also have to expect that our device may have died.
 */
#include <sys/sbuf.h>
extern struct mtx devmtx;
extern int devfs_dev_exists(const char *);

static void
zvol_wait_for_dev(const char *name)
{
	boolean_t done;
	struct sbuf *sb;

	sb = sbuf_new_auto();
	sbuf_printf(sb, "%s/%s", ZVOL_DRIVER, name);
	sbuf_finish(sb);
	for (;;) {
		g_topology_lock();
		done = (zvol_geom_lookup(name) == NULL);
		g_topology_unlock();
		if (!done) {
			mtx_lock(&devmtx);
			done = (devfs_dev_exists(sbuf_data(sb)) == 1);
			mtx_unlock(&devmtx);
		}
		if (done)
			break;
		delay(10);
	}
	sbuf_delete(sb);
}
/************************************************************************/

static void
zvol_rename_device(struct zvol_iterate_arg *zvi, struct g_provider *pp,
    const char *newname)
{

	zvol_geom_create(newname);
	/*
	 * By doing the destroy after the create, we should cause the devfs
	 * node for the new device to appear before returning.
	 */
	zvol_geom_destroy(pp->private, zvi);
}

static int
zvol_geom_open(struct g_provider *pp, int flag, int count)
{
	zvol_freebsd_state_t *zvf = pp->private;
	zvol_state_t *zv;
	int error;

	if (zvf == NULL)
		return (ENXIO);

	if (tsd_get(zfs_geom_probe_vdev_key) != NULL) {
		/*
		 * if zfs_geom_probe_vdev_key is set, that means that zfs is
		 * attempting to probe geom providers while looking for a
		 * replacement for a missing VDEV.  It is illegal to use a
		 * zvol as a vdev.  Deadlocks can result if another thread has
		 * spa_namespace_lock
		 */
		return (EOPNOTSUPP);
	}

	g_topology_unlock();
	error = zvol_open(ZVF_GEOM_NAME(pp), flag, count, &zv);
	g_topology_lock();

	if (error == 0) {
		mtx_lock(&zvf->zvf_mtx);
		if (zvf->zv == NULL)
			zvf->zv = zv;
		else if (zvf->zv != zv)
			error = ENXIO;
		mtx_unlock(&zvf->zvf_mtx);
		if (error != 0) {
			ZFS_LOG(0, "%s: bad open on %s", __func__,
			    ZVF_GEOM_NAME(pp));
			zvol_close(zv, count);
		}
	}

	return (error);
}

static int
zvol_geom_close(struct g_provider *pp, int flag, int count, int curholds)
{
	zvol_freebsd_state_t *zvf = pp->private;
	zvol_state_t *zv;

	/*
	 * 'count' is technically passed as r+w+e from zvol_geom_access.  So
	 * if it matches the current holds, then this is the last close for
	 * the GEOM device.  It may not, however, be the last close for the
	 * zvol object itself, so the zv pointer must be cleared here anyway.
	 *
	 * Clearing the zv state must be done first, in order to prevent any
	 * spurious last closes that may occur due to the need to drop the
	 * topology lock while calling zvol_close().
	 */
	mtx_lock(&zvf->zvf_mtx);
	zv = zvf->zv;
	if (zv == NULL) {
		mtx_unlock(&zvf->zvf_mtx);
		return (0);
	}
	if (curholds == count) {
		zvf->zv = NULL;
		/* Inform anyone that might be waiting for this. */
		wakeup(&zvf->zvf_state);
	}
	mtx_unlock(&zvf->zvf_mtx);

	g_topology_unlock();
	zvol_close(zv, count);
	g_topology_lock();

	return (0);
}

/*
 * Use another layer on top of zvol_dmu_state_t to provide additional
 * context specific to zvol_freebsd_strategy(), namely, the bio and the done
 * callback, which calls zvol_dmu_done, as is done for zvol_dmu_state_t.
 */
typedef struct zvol_strategy_state {
	zvol_dmu_state_t zds;
	struct bio *bp;
} zvol_strategy_state_t;

static void
zvol_strategy_dmu_done(dmu_context_t *dmu_ctx)
{
	zvol_strategy_state_t *zss = (zvol_strategy_state_t *)dmu_ctx;

	zvol_dmu_done(dmu_ctx);
	zss->bp->bio_completed = dmu_ctx->completed_size;
	g_io_deliver(zss->bp, dmu_ctx->err);
	kmem_free(zss, sizeof(zvol_strategy_state_t));
}

static void
zvol_geom_strategy(struct bio *bp)
{
	zvol_freebsd_state_t *zvf = bp->bio_to->private;
	zvol_strategy_state_t *zss;
	int error = 0;
	uint32_t dmu_flags = DMU_CTX_FLAG_ASYNC;

	if (zvf == NULL || zvf->zv == NULL) {
		g_io_deliver(bp, ENXIO);
		return;
	}

	if (bp->bio_cmd == BIO_READ)
		dmu_flags |= DMU_CTX_FLAG_READ;

	zss = kmem_zalloc(sizeof(zvol_strategy_state_t), KM_SLEEP);
	zss->bp = bp;
	zss->zds.zv = zvf->zv;

	error = zvol_dmu_context_init(&zss->zds, bp->bio_data, bp->bio_offset,
	    bp->bio_length, dmu_flags, zvol_strategy_dmu_done);
	if (error) {
		kmem_free(zss, sizeof(zvol_strategy_state_t));
		g_io_deliver(bp, ENXIO);
		return;
	}

	/* Errors are reported via the callback. */
	zvol_dmu_issue(&zss->zds);
}

static int
zvol_geom_access(struct g_provider *pp, int dcr, int dcw, int dce)
{
	int count, error, flags;

	g_topology_assert();

	/*
	 * To make it easier we expect either open or close, but not both
	 * at the same time.
	 */
	KASSERT((dcr >= 0 && dcw >= 0 && dce >= 0) ||
	    (dcr <= 0 && dcw <= 0 && dce <= 0),
	    ("Unsupported access request to %s (dcr=%d, dcw=%d, dce=%d).",
	    pp->name, dcr, dcw, dce));

	if (pp->private == NULL) {
		if (dcr <= 0 && dcw <= 0 && dce <= 0)
			return (0);
		return (pp->error ? pp->error : ENXIO);
	}

	/*
	 * We don't pass FEXCL flag to zvol_open()/zvol_close() if dce != 0,
	 * because GEOM already handles that and handles it a bit differently.
	 * GEOM allows for multiple read/exclusive consumers and ZFS allows
	 * only one exclusive consumer, no matter if it is reader or writer.
	 * I like better the way GEOM works so I'll leave it for GEOM to
	 * decide what to do.
	 */

	count = dcr + dcw + dce;
	if (count == 0)
		return (0);

	flags = 0;
	if (dcr != 0 || dce != 0)
		flags |= FREAD;
	if (dcw != 0)
		flags |= FWRITE;

	if (count > 0)
		error = zvol_geom_open(pp, flags, count);
	else
		error = zvol_geom_close(pp, flags, -count,
		    pp->acr + pp->acw + pp->ace);
	return (error);
}

static void
zvol_geom_start(struct bio *bp)
{
	zvol_freebsd_state_t *zvf;
	boolean_t first = B_FALSE, inserted = B_FALSE;

	switch (bp->bio_cmd) {
	case BIO_READ:
	case BIO_WRITE:
	case BIO_FLUSH:
		zvf = bp->bio_to->private;
		ASSERT(zvf != NULL);
		mtx_lock(&zvf->zvf_mtx);
		inserted = (zvf->zvf_state == ZVF_STATE_OPERATIONAL);
		if (inserted) {
			first = (bioq_first(&zvf->zvf_queue) == NULL);
			bioq_insert_tail(&zvf->zvf_queue, bp);
		}
		mtx_unlock(&zvf->zvf_mtx);
		if (first)
			wakeup_one(&zvf->zvf_queue);
		if (!inserted)
			g_io_deliver(bp, ENXIO);
		break;
	case BIO_GETATTR:
	case BIO_DELETE:
	default:
		g_io_deliver(bp, EOPNOTSUPP);
		break;
	}
}

static void
zvol_device_worker(void *arg)
{
	zvol_freebsd_state_t *zvf;
	struct bio *bp;
	int running;

	thread_lock(curthread);
	sched_prio(curthread, PRIBIO);
	thread_unlock(curthread);

	/* Do some setup.  This is done here to avoid deadlocks. */
	zvf = arg;
	mtx_lock(&zvf->zvf_mtx);
	running = (zvf->zvf_state == ZVF_STATE_SETUP);
	if (running)
		zvol_geom_setstate(zvf, ZVF_STATE_OPERATIONAL);
	mtx_unlock(&zvf->zvf_mtx);
	if (running)
		VERIFY0(zvol_geom_info(ZVF_GEOM_NAME(zvf->zvf_provider),
		    &zvf->zvf_provider->mediasize));

	for (;;) {
		mtx_lock(&zvf->zvf_mtx);
		bp = bioq_takefirst(&zvf->zvf_queue);
		if (bp == NULL) {
			if (zvf->zvf_state == ZVF_STATE_DESTROY) {
				zvol_geom_setstate(zvf, ZVF_STATE_GONE);
				mtx_unlock(&zvf->zvf_mtx);
				kthread_exit();
			}
			mtx_sleep(&zvf->zvf_queue, &zvf->zvf_mtx,
			    PRIBIO | PDROP, "zvol:io", 0);
			continue;
		}
		mtx_unlock(&zvf->zvf_mtx);
		switch (bp->bio_cmd) {
		case BIO_FLUSH:
			zil_commit(zvf->zv->zv_zilog, ZVOL_OBJ);
			g_io_deliver(bp, 0);
			break;
		case BIO_READ:
		case BIO_WRITE:
			zvol_geom_strategy(bp);
			break;
		}
	}
}

static boolean_t
dsl_dataset_is_zvol(dsl_dataset_t *ds)
{
	objset_t *os;

	if (dmu_objset_from_ds(ds, &os) != 0 ||
	    dmu_objset_type(os) != DMU_OST_ZVOL)
		return (B_FALSE);
	return (B_TRUE);
}

static void
zvol_snapshot_sync(dsl_dataset_snapshot_arg_t *ddsa, dsl_dataset_t *snap_ds,
    char *snap_dsname)
{
	objset_t *os;

	if (dsl_dataset_is_zvol(snap_ds))
		VERIFY0(zvol_create_device(snap_dsname, NULL));
}

static void
zvol_snapshot_cleanup(dsl_dataset_snapshot_arg_t *ddsa)
{
	nvpair_t *pair;

	for (pair = nvlist_next_nvpair(ddsa->ddsa_snaps, NULL);
	    pair != NULL; pair = nvlist_next_nvpair(ddsa->ddsa_snaps, pair))
		zvol_wait_for_dev(nvpair_name(pair));
}

int
zvol_snapshot_init(dsl_dataset_snapshot_arg_t *ddsa)
{

#ifdef _KERNEL
	ddsa->ddsa_user_syncfunc = zvol_snapshot_sync;
	ddsa->ddsa_user_cleanupfunc = zvol_snapshot_cleanup;
#endif
	return (0);
}

typedef void (*zvol_rename_devices_cb)(struct zvol_iterate_arg *,
    struct g_provider *, char *, size_t, void *);

static void
zvol_rename_devices_impl(const char *oldname, void *data,
    zvol_rename_devices_cb func)
{
	char name[MAXPATHLEN];
	struct g_provider *pp;
	struct g_geom *gp, *gptmp;
	size_t namelen;
	struct zvol_iterate_arg *zvi;

	zvi = zvol_create_iteration();
	namelen = strlen(oldname);

	DROP_GIANT();
	g_topology_lock();

	LIST_FOREACH_SAFE(gp, &zfs_zvol_class.geom, geom, gptmp) {
		pp = LIST_FIRST(&gp->provider);
		if (pp == NULL || pp->private == NULL)
			continue;
		if (strncmp(ZVF_GEOM_NAME(pp), oldname, namelen) != 0)
			continue;
		func(zvi, pp, name, namelen, data);
	}

	g_topology_unlock();
	PICKUP_GIANT();
	zvol_iterate_wait_and_destroy(zvi);
}

static void
zvol_rename_dsl_dir(struct zvol_iterate_arg *zvi, struct g_provider *pp,
    char *namestr, size_t namelen, void *data)
{
	dsl_dir_rename_arg_t *ddra = data;
	char *geom_name = ZVF_GEOM_NAME(pp);

	if (geom_name[namelen] != '\0' && geom_name[namelen] != '/' &&
	    geom_name[namelen] != '@')
		return;

	snprintf(namestr, MAXPATHLEN, "%s%s", ddra->ddra_newname,
	    &geom_name[namelen]);
	zvol_rename_device(zvi, pp, namestr);
}

void
zvol_rename_cleanup(dsl_dir_rename_arg_t *ddra)
{
	if (ddra->ddra_error != 0)
		return;
	zvol_rename_devices_impl(ddra->ddra_oldname, ddra, zvol_rename_dsl_dir);
}

static void
zvol_rename_snapshot(struct zvol_iterate_arg *zvi, struct g_provider *pp,
    char *namestr, size_t namelen, void *data)
{
	dsl_dataset_rename_snapshot_arg_t *ddrsa = data;
	char *geom_name = ZVF_GEOM_NAME(pp);
	char *cursnap;

	if (geom_name[namelen] != '@' && geom_name[namelen] != '/')
		return;
	strlcpy(namestr, geom_name, MAXPATHLEN);
	cursnap = strchr(&namestr[namelen], '@');
	if (cursnap == NULL)
		return;
	cursnap += 1; /* skip past the '@' */
	if (strcmp(cursnap, ddrsa->ddrsa_oldsnapname) != 0)
		return;
	strlcpy(cursnap, ddrsa->ddrsa_newsnapname,
	    MAXPATHLEN - (cursnap - namestr));
	zvol_rename_device(zvi, pp, namestr);
}

void
zvol_rename_snapshot_cleanup(dsl_dataset_rename_snapshot_arg_t *ddrsa)
{
	if (ddrsa->ddrsa_error != 0)
		return;
	zvol_rename_devices_impl(ddrsa->ddrsa_fsname, ddrsa,
	    zvol_rename_snapshot);
}

struct zvol_clone_state {
	char zcs_dsname[MAXNAMELEN];
};

static void
zvol_clone_sync(dmu_objset_clone_arg_t *doca, dsl_dataset_t *clone_ds)
{
	if (dsl_dataset_is_zvol(clone_ds)) {
		struct zvol_clone_state *zcs = doca->doca_user_data;
		VERIFY0(zvol_device_perform(clone_ds, zvol_create_device,
		    zcs->zcs_dsname));
	}
}
static void
zvol_clone_cleanup(dmu_objset_clone_arg_t *doca)
{
	struct zvol_clone_state *zcs = doca->doca_user_data;
	if (zcs->zcs_dsname[0] != '\0')
		zvol_wait_for_dev(zcs->zcs_dsname);
	kmem_free(zcs, sizeof(*zcs));
}

int
zvol_clone_init(dmu_objset_clone_arg_t *doca)
{
#ifdef _KERNEL
	struct zvol_clone_state *zcs = kmem_zalloc(sizeof(*zcs), KM_SLEEP);

	doca->doca_user_syncfunc = zvol_clone_sync;
	doca->doca_user_cleanupfunc = zvol_clone_cleanup;
	doca->doca_user_data = zcs;
#endif
	return (0);
}

void
zvol_create_cleanup(dmu_objset_create_arg_t *doca)
{
	if (doca->doca_error == 0 && doca->doca_userfunc == zvol_create_cb)
		zvol_wait_for_dev(doca->doca_name);
}

int
zvol_create_init(dmu_objset_create_arg_t *doca)
{

#ifdef _KERNEL
	doca->doca_user_cleanupfunc = zvol_create_cleanup;
#endif
	return (0);
}

static void
zvol_destroy_devname(dsl_dataset_t *ds, const char *dsname,
    struct zvol_iterate_arg *zvi)
{
	if (dsl_dataset_is_zvol(ds))
		VERIFY0(zvol_destroy_device(dsname, zvi));
}

static void
zvol_destroy_snaps_sync(dmu_snapshots_destroy_arg_t *dsda, dsl_pool_t *dp,
    dsl_dataset_t *ds, const char *dsname)
{
	dsl_dataset_t *head_ds;

	/*
	 * When destroying a snapshot, must check the type of its parent
	 * dataset, not the snapshot's dataset, whose type is snapshot
	 * rather than zvol.
	 */
	VERIFY0(dsl_dataset_hold_obj(dp,
	    ds->ds_dir->dd_phys->dd_head_dataset_obj, FTAG, &head_ds));
	zvol_destroy_devname(head_ds, dsname, dsda->dsda_user_data);
	dsl_dataset_rele(head_ds, FTAG);
}

static void
zvol_destroy_snaps_cleanup(dmu_snapshots_destroy_arg_t *dsda)
{
	zvol_iterate_wait_and_destroy(dsda->dsda_user_data);
}

int
zvol_destroy_snaps_init(dmu_snapshots_destroy_arg_t *dsda)
{

#ifdef _KERNEL
	dsda->dsda_user_data = zvol_create_iteration();
	dsda->dsda_user_syncfunc = zvol_destroy_snaps_sync;
	dsda->dsda_user_cleanupfunc = zvol_destroy_snaps_cleanup;
#endif
	return (0);
}

static void
zvol_destroy_head_sync(dsl_destroy_head_arg_t *ddha, dsl_dataset_t *ds)
{
	zvol_destroy_devname(ds, ddha->ddha_name, ddha->ddha_user_data);
}

static void
zvol_destroy_head_cleanup(dsl_destroy_head_arg_t *ddha)
{
	zvol_iterate_wait_and_destroy(ddha->ddha_user_data);
}

int
zvol_destroy_head_init(dsl_destroy_head_arg_t *ddha)
{

#ifdef _KERNEL
	ddha->ddha_user_data = zvol_create_iteration();
	ddha->ddha_user_syncfunc = zvol_destroy_head_sync;
	ddha->ddha_user_cleanupfunc = zvol_destroy_head_cleanup;
#endif
	return (0);
}

void
zvol_os_init()
{

	ZFS_LOG(1, "ZVOL Initialized.");
}

void
zvol_os_fini()
{

	ZFS_LOG(1, "ZVOL Deinitialized.");
}

int
zvol_physio(zvol_state_t *zv, uio_t *uio)
{
	VERIFY(!"zvol_physio not implemented");
	return (EIO);
}

void
zvol_generate_lun_expansion_event(zvol_state_t *zv)
{
	/* N/A on FreeBSD */
}
