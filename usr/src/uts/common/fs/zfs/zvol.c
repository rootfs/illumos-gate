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
 * ZFS volume emulation driver.
 *
 * Makes a DMU object look like a volume of arbitrary size, up to 2^64 bytes.
 * Volumes are accessed through the symbolic links named:
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
#include <sys/sunddi.h>
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
#include <sys/dsl_dir.h>

#include "zfs_namecheck.h"

/*
 * This lock protects the zfsdev_state structure from being modified
 * while it's being used, e.g. an open that comes in before a create
 * finishes.  It also protects temporary opens of the dataset so that,
 * e.g., an open doesn't get a spurious EBUSY.
 */
kmutex_t zfsdev_state_lock;
void *zfsdev_state;
static char *zvol_tag = "zvol_tag";

#define	ZVOL_DUMPSIZE		"dumpsize"

uint32_t zvol_devices;

static int zvol_dumpify(zvol_state_t *zv);
static int zvol_dump_fini(zvol_state_t *zv);
static int zvol_dump_init(zvol_state_t *zv, boolean_t resize);

int
zvol_check_volsize(uint64_t volsize, uint64_t blocksize)
{
	if (volsize == 0)
		return (SET_ERROR(EINVAL));

	if (volsize % blocksize != 0)
		return (SET_ERROR(EINVAL));

#ifdef _ILP32
	if (volsize - 1 > SPEC_MAXOFFSET_T)
		return (SET_ERROR(EOVERFLOW));
#endif
	return (0);
}

int
zvol_check_volblocksize(uint64_t volblocksize)
{
	if (volblocksize < SPA_MINBLOCKSIZE ||
	    volblocksize > SPA_MAXBLOCKSIZE ||
	    !ISP2(volblocksize))
		return (SET_ERROR(EDOM));

	return (0);
}

int
zvol_get_stats(objset_t *os, nvlist_t *nv)
{
	int error;
	dmu_object_info_t doi;
	uint64_t val;

	error = zap_lookup(os, ZVOL_ZAP_OBJ, "size", 8, 1, &val);
	if (error)
		return (error);

	dsl_prop_nvlist_add_uint64(nv, ZFS_PROP_VOLSIZE, val);

	error = dmu_object_info(os, ZVOL_OBJ, &doi);

	if (error == 0) {
		dsl_prop_nvlist_add_uint64(nv, ZFS_PROP_VOLBLOCKSIZE,
		    doi.doi_data_block_size);
	}

	return (error);
}

static int
zvol_dumpify_size_change(zvol_state_t *zv, objset_t *os, uint64_t volsize)
{
	int error = 0;

#ifdef ZVOL_DUMP
	if ((zv->zv_flags & ZVOL_DUMPIFIED) == 0)
		return (0);

	old_volsize = zv->zv_volsize;
	zv->zv_volsize = volsize;

	error = zvol_dumpify(zv);
	if (error == 0)
		error = dumpvp_resize();
	if (error) {
		(void) zvol_update_volsize(os, old_volsize);
		zv->zv_volsize = old_volsize;
		error = zvol_dumpify(zv);
	}
#endif
	return (error);
}

#ifdef ZVOL_DUMP
/* extent mapping arg */
struct maparg {
	zvol_state_t	*ma_zv;
	uint64_t	ma_blks;
};

/*ARGSUSED*/
static int
zvol_map_block(spa_t *spa, zilog_t *zilog, const blkptr_t *bp, arc_buf_t *pbuf,
    const zbookmark_t *zb, const dnode_phys_t *dnp, void *arg)
{
	struct maparg *ma = arg;
	zvol_extent_t *ze;
	int bs = ma->ma_zv->zv_volblocksize;

	if (bp == NULL || zb->zb_object != ZVOL_OBJ || zb->zb_level != 0)
		return (0);

	VERIFY3U(ma->ma_blks, ==, zb->zb_blkid);
	ma->ma_blks++;

	/* Abort immediately if we have encountered gang blocks */
	if (BP_IS_GANG(bp))
		return (SET_ERROR(EFRAGS));

	/*
	 * See if the block is at the end of the previous extent.
	 */
	ze = list_tail(&ma->ma_zv->zv_extents);
	if (ze &&
	    DVA_GET_VDEV(BP_IDENTITY(bp)) == DVA_GET_VDEV(&ze->ze_dva) &&
	    DVA_GET_OFFSET(BP_IDENTITY(bp)) ==
	    DVA_GET_OFFSET(&ze->ze_dva) + ze->ze_nblks * bs) {
		ze->ze_nblks++;
		return (0);
	}

	dprintf_bp(bp, "%s", "next blkptr:");

	/* start a new extent */
	ze = kmem_zalloc(sizeof (zvol_extent_t), KM_SLEEP);
	ze->ze_dva = bp->blk_dva[0];	/* structure assignment */
	ze->ze_nblks = 1;
	list_insert_tail(&ma->ma_zv->zv_extents, ze);
	return (0);
}

static void
zvol_free_extents(zvol_state_t *zv)
{
	zvol_extent_t *ze;

	while (ze = list_head(&zv->zv_extents)) {
		list_remove(&zv->zv_extents, ze);
		kmem_free(ze, sizeof (zvol_extent_t));
	}
}

static int
zvol_get_lbas(zvol_state_t *zv)
{
	objset_t *os = zv->zv_objset;
	struct maparg	ma;
	int		err;

	ma.ma_zv = zv;
	ma.ma_blks = 0;
	zvol_free_extents(zv);

	/* commit any in-flight changes before traversing the dataset */
	txg_wait_synced(dmu_objset_pool(os), 0);
	err = traverse_dataset(dmu_objset_ds(os), 0,
	    TRAVERSE_PRE | TRAVERSE_PREFETCH_METADATA, zvol_map_block, &ma);
	if (err || ma.ma_blks != (zv->zv_volsize / zv->zv_volblocksize)) {
		zvol_free_extents(zv);
		return (err ? err : SET_ERROR(EIO));
	}

	return (0);
}

int
zvol_prealloc(zvol_state_t *zv)
{
	objset_t *os = zv->zv_objset;
	dmu_tx_t *tx;
	uint64_t refd, avail, usedobjs, availobjs;
	uint64_t resid = zv->zv_volsize;
	uint64_t off = 0;

	/* Check the space usage before attempting to allocate the space */
	dmu_objset_space(os, &refd, &avail, &usedobjs, &availobjs);
	if (avail < zv->zv_volsize)
		return (SET_ERROR(ENOSPC));

	/* Free old extents if they exist */
	zvol_free_extents(zv);

	while (resid != 0) {
		int error;
		uint64_t bytes = MIN(resid, SPA_MAXBLOCKSIZE);

		tx = dmu_tx_create(os);
		dmu_tx_hold_write(tx, ZVOL_OBJ, off, bytes);
		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error == 0)
			error = dmu_prealloc(os, ZVOL_OBJ, off, bytes, tx);
		if (error) {
			dmu_tx_abort(tx);
			(void) dmu_free_long_range(os, ZVOL_OBJ, 0, off);
			return (error);
		}
		dmu_tx_commit(tx);
		off += bytes;
		resid -= bytes;
	}
	txg_wait_synced(dmu_objset_pool(os), 0);

	return (0);
}

static int
zvol_dump_init(zvol_state_t *zv, boolean_t resize)
{
	dmu_tx_t *tx;
	int error = 0;
	objset_t *os = zv->zv_objset;
	nvlist_t *nv = NULL;
	uint64_t version = spa_version(dmu_objset_spa(zv->zv_objset));

	ASSERT(MUTEX_HELD(&zfsdev_state_lock));
	error = dmu_free_long_range(zv->zv_objset, ZVOL_OBJ, 0,
	    DMU_OBJECT_END);
	/* wait for dmu_free_long_range to actually free the blocks */
	txg_wait_synced(dmu_objset_pool(zv->zv_objset), 0);

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, ZVOL_ZAP_OBJ, TRUE, NULL);
	dmu_tx_hold_bonus(tx, ZVOL_OBJ);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		return (error);
	}

	/*
	 * If we are resizing the dump device then we only need to
	 * update the refreservation to match the newly updated
	 * zvolsize. Otherwise, we save off the original state of the
	 * zvol so that we can restore them if the zvol is ever undumpified.
	 */
	if (resize) {
		error = zap_update(os, ZVOL_ZAP_OBJ,
		    zfs_prop_to_name(ZFS_PROP_REFRESERVATION), 8, 1,
		    &zv->zv_volsize, tx);
	} else {
		uint64_t checksum, compress, refresrv, vbs, dedup;

		error = dsl_prop_get_integer(zv->zv_name,
		    zfs_prop_to_name(ZFS_PROP_COMPRESSION), &compress, NULL);
		error = error ? error : dsl_prop_get_integer(zv->zv_name,
		    zfs_prop_to_name(ZFS_PROP_CHECKSUM), &checksum, NULL);
		error = error ? error : dsl_prop_get_integer(zv->zv_name,
		    zfs_prop_to_name(ZFS_PROP_REFRESERVATION), &refresrv, NULL);
		error = error ? error : dsl_prop_get_integer(zv->zv_name,
		    zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE), &vbs, NULL);
		if (version >= SPA_VERSION_DEDUP) {
			error = error ? error :
			    dsl_prop_get_integer(zv->zv_name,
			    zfs_prop_to_name(ZFS_PROP_DEDUP), &dedup, NULL);
		}

		error = error ? error : zap_update(os, ZVOL_ZAP_OBJ,
		    zfs_prop_to_name(ZFS_PROP_COMPRESSION), 8, 1,
		    &compress, tx);
		error = error ? error : zap_update(os, ZVOL_ZAP_OBJ,
		    zfs_prop_to_name(ZFS_PROP_CHECKSUM), 8, 1, &checksum, tx);
		error = error ? error : zap_update(os, ZVOL_ZAP_OBJ,
		    zfs_prop_to_name(ZFS_PROP_REFRESERVATION), 8, 1,
		    &refresrv, tx);
		error = error ? error : zap_update(os, ZVOL_ZAP_OBJ,
		    zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE), 8, 1,
		    &vbs, tx);
		error = error ? error : dmu_object_set_blocksize(
		    os, ZVOL_OBJ, SPA_MAXBLOCKSIZE, 0, tx);
		if (version >= SPA_VERSION_DEDUP) {
			error = error ? error : zap_update(os, ZVOL_ZAP_OBJ,
			    zfs_prop_to_name(ZFS_PROP_DEDUP), 8, 1,
			    &dedup, tx);
		}
		if (error == 0)
			zv->zv_volblocksize = SPA_MAXBLOCKSIZE;
	}
	dmu_tx_commit(tx);

	/*
	 * We only need update the zvol's property if we are initializing
	 * the dump area for the first time.
	 */
	if (!resize) {
		VERIFY(nvlist_alloc(&nv, NV_UNIQUE_NAME, KM_SLEEP) == 0);
		VERIFY(nvlist_add_uint64(nv,
		    zfs_prop_to_name(ZFS_PROP_REFRESERVATION), 0) == 0);
		VERIFY(nvlist_add_uint64(nv,
		    zfs_prop_to_name(ZFS_PROP_COMPRESSION),
		    ZIO_COMPRESS_OFF) == 0);
		VERIFY(nvlist_add_uint64(nv,
		    zfs_prop_to_name(ZFS_PROP_CHECKSUM),
		    ZIO_CHECKSUM_OFF) == 0);
		if (version >= SPA_VERSION_DEDUP) {
			VERIFY(nvlist_add_uint64(nv,
			    zfs_prop_to_name(ZFS_PROP_DEDUP),
			    ZIO_CHECKSUM_OFF) == 0);
		}

		error = zfs_set_prop_nvlist(zv->zv_name, ZPROP_SRC_LOCAL,
		    nv, NULL);
		nvlist_free(nv);

		if (error)
			return (error);
	}

	/* Allocate the space for the dump */
	error = zvol_prealloc(zv);
	return (error);
}

static int
zvol_dumpify(zvol_state_t *zv)
{
	int error = 0;
	uint64_t dumpsize = 0;
	dmu_tx_t *tx;
	objset_t *os = zv->zv_objset;

	if (zv->zv_flags & ZVOL_RDONLY)
		return (SET_ERROR(EROFS));

	if (zap_lookup(zv->zv_objset, ZVOL_ZAP_OBJ, ZVOL_DUMPSIZE,
	    8, 1, &dumpsize) != 0 || dumpsize != zv->zv_volsize) {
		boolean_t resize = (dumpsize > 0) ? B_TRUE : B_FALSE;

		if ((error = zvol_dump_init(zv, resize)) != 0) {
			(void) zvol_dump_fini(zv);
			return (error);
		}
	}

	/*
	 * Build up our lba mapping.
	 */
	error = zvol_get_lbas(zv);
	if (error) {
		(void) zvol_dump_fini(zv);
		return (error);
	}

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, ZVOL_ZAP_OBJ, TRUE, NULL);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		(void) zvol_dump_fini(zv);
		return (error);
	}

	zv->zv_flags |= ZVOL_DUMPIFIED;
	error = zap_update(os, ZVOL_ZAP_OBJ, ZVOL_DUMPSIZE, 8, 1,
	    &zv->zv_volsize, tx);
	dmu_tx_commit(tx);

	if (error) {
		(void) zvol_dump_fini(zv);
		return (error);
	}

	txg_wait_synced(dmu_objset_pool(os), 0);
	return (0);
}

static int
zvol_dump_fini(zvol_state_t *zv)
{
	dmu_tx_t *tx;
	objset_t *os = zv->zv_objset;
	nvlist_t *nv;
	int error = 0;
	uint64_t checksum, compress, refresrv, vbs, dedup;
	uint64_t version = spa_version(dmu_objset_spa(zv->zv_objset));

	/*
	 * Attempt to restore the zvol back to its pre-dumpified state.
	 * This is a best-effort attempt as it's possible that not all
	 * of these properties were initialized during the dumpify process
	 * (i.e. error during zvol_dump_init).
	 */

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, ZVOL_ZAP_OBJ, TRUE, NULL);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		return (error);
	}
	(void) zap_remove(os, ZVOL_ZAP_OBJ, ZVOL_DUMPSIZE, tx);
	dmu_tx_commit(tx);

	(void) zap_lookup(zv->zv_objset, ZVOL_ZAP_OBJ,
	    zfs_prop_to_name(ZFS_PROP_CHECKSUM), 8, 1, &checksum);
	(void) zap_lookup(zv->zv_objset, ZVOL_ZAP_OBJ,
	    zfs_prop_to_name(ZFS_PROP_COMPRESSION), 8, 1, &compress);
	(void) zap_lookup(zv->zv_objset, ZVOL_ZAP_OBJ,
	    zfs_prop_to_name(ZFS_PROP_REFRESERVATION), 8, 1, &refresrv);
	(void) zap_lookup(zv->zv_objset, ZVOL_ZAP_OBJ,
	    zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE), 8, 1, &vbs);

	VERIFY(nvlist_alloc(&nv, NV_UNIQUE_NAME, KM_SLEEP) == 0);
	(void) nvlist_add_uint64(nv,
	    zfs_prop_to_name(ZFS_PROP_CHECKSUM), checksum);
	(void) nvlist_add_uint64(nv,
	    zfs_prop_to_name(ZFS_PROP_COMPRESSION), compress);
	(void) nvlist_add_uint64(nv,
	    zfs_prop_to_name(ZFS_PROP_REFRESERVATION), refresrv);
	if (version >= SPA_VERSION_DEDUP &&
	    zap_lookup(zv->zv_objset, ZVOL_ZAP_OBJ,
	    zfs_prop_to_name(ZFS_PROP_DEDUP), 8, 1, &dedup) == 0) {
		(void) nvlist_add_uint64(nv,
		    zfs_prop_to_name(ZFS_PROP_DEDUP), dedup);
	}
	(void) zfs_set_prop_nvlist(zv->zv_name, ZPROP_SRC_LOCAL,
	    nv, NULL);
	nvlist_free(nv);

	zvol_free_extents(zv);
	zv->zv_flags &= ~ZVOL_DUMPIFIED;
	(void) dmu_free_long_range(os, ZVOL_OBJ, 0, DMU_OBJECT_END);
	/* wait for dmu_free_long_range to actually free the blocks */
	txg_wait_synced(dmu_objset_pool(zv->zv_objset), 0);
	tx = dmu_tx_create(os);
	dmu_tx_hold_bonus(tx, ZVOL_OBJ);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		return (error);
	}
	if (dmu_object_set_blocksize(os, ZVOL_OBJ, vbs, 0, tx) == 0)
		zv->zv_volblocksize = vbs;
	dmu_tx_commit(tx);

	return (0);
}

static int
zvol_dumpio_vdev(vdev_t *vd, void *addr, uint64_t offset, uint64_t size,
    boolean_t doread, boolean_t isdump)
{
	vdev_disk_t *dvd;
	int c;
	int numerrors = 0;

	for (c = 0; c < vd->vdev_children; c++) {
		ASSERT(vd->vdev_ops == &vdev_mirror_ops ||
		    vd->vdev_ops == &vdev_replacing_ops ||
		    vd->vdev_ops == &vdev_spare_ops);
		int err = zvol_dumpio_vdev(vd->vdev_child[c],
		    addr, offset, size, doread, isdump);
		if (err != 0) {
			numerrors++;
		} else if (doread) {
			break;
		}
	}

	if (!vd->vdev_ops->vdev_op_leaf)
		return (numerrors < vd->vdev_children ? 0 : SET_ERROR(EIO));

	if (doread && !vdev_readable(vd))
		return (SET_ERROR(EIO));
	else if (!doread && !vdev_writeable(vd))
		return (SET_ERROR(EIO));

	dvd = vd->vdev_tsd;
	ASSERT3P(dvd, !=, NULL);
	offset += VDEV_LABEL_START_SIZE;

	if (ddi_in_panic() || isdump) {
		ASSERT(!doread);
		if (doread)
			return (SET_ERROR(EIO));
		return (ldi_dump(dvd->vd_lh, addr, lbtodb(offset),
		    lbtodb(size)));
	} else {
		return (vdev_disk_physio(dvd->vd_lh, addr, size, offset,
		    doread ? B_READ : B_WRITE));
	}
}

static int
zvol_dumpio(zvol_state_t *zv, void *addr, uint64_t offset, uint64_t size,
    boolean_t doread, boolean_t isdump)
{
	vdev_t *vd;
	int error;
	zvol_extent_t *ze;
	spa_t *spa = dmu_objset_spa(zv->zv_objset);

	/* Must be sector aligned, and not stradle a block boundary. */
	if (P2PHASE(offset, DEV_BSIZE) || P2PHASE(size, DEV_BSIZE) ||
	    P2BOUNDARY(offset, size, zv->zv_volblocksize)) {
		return (SET_ERROR(EINVAL));
	}
	ASSERT(size <= zv->zv_volblocksize);

	/* Locate the extent this belongs to */
	ze = list_head(&zv->zv_extents);
	while (offset >= ze->ze_nblks * zv->zv_volblocksize) {
		offset -= ze->ze_nblks * zv->zv_volblocksize;
		ze = list_next(&zv->zv_extents, ze);
	}

	if (ze == NULL)
		return (SET_ERROR(EINVAL));

	if (!ddi_in_panic())
		spa_config_enter(spa, SCL_STATE, FTAG, RW_READER);

	vd = vdev_lookup_top(spa, DVA_GET_VDEV(&ze->ze_dva));
	offset += DVA_GET_OFFSET(&ze->ze_dva);
	error = zvol_dumpio_vdev(vd, addr, offset, size, doread, isdump);

	if (!ddi_in_panic())
		spa_config_exit(spa, SCL_STATE, FTAG);

	return (error);
}
#endif	/* ZVOL_DUMP */

/* ARGSUSED */
void
zvol_create_cb(objset_t *os, void *arg, cred_t *cr, dmu_tx_t *tx)
{
	zfs_creat_t *zct = arg;
	nvlist_t *nvprops = zct->zct_props;
	int error;
	uint64_t volblocksize, volsize;

	VERIFY(nvlist_lookup_uint64(nvprops,
	    zfs_prop_to_name(ZFS_PROP_VOLSIZE), &volsize) == 0);
	if (nvlist_lookup_uint64(nvprops,
	    zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE), &volblocksize) != 0)
		volblocksize = zfs_prop_default_numeric(ZFS_PROP_VOLBLOCKSIZE);

	/*
	 * These properties must be removed from the list so the generic
	 * property setting step won't apply to them.
	 */
	VERIFY(nvlist_remove_all(nvprops,
	    zfs_prop_to_name(ZFS_PROP_VOLSIZE)) == 0);
	(void) nvlist_remove_all(nvprops,
	    zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE));

	error = dmu_object_claim(os, ZVOL_OBJ, DMU_OT_ZVOL, volblocksize,
	    DMU_OT_NONE, 0, tx);
	ASSERT(error == 0);

	error = zap_create_claim(os, ZVOL_ZAP_OBJ, DMU_OT_ZVOL_PROP,
	    DMU_OT_NONE, 0, tx);
	ASSERT(error == 0);

	error = zap_update(os, ZVOL_ZAP_OBJ, "size", 8, 1, &volsize, tx);
	ASSERT(error == 0);

#ifdef _KERNEL
	{
		char *namestr = kmem_alloc(MAXNAMELEN, KM_SLEEP);
		*namestr = '\0';
		VERIFY0(zvol_device_perform(os->os_dsl_dataset,
		    zvol_create_device, namestr));
		kmem_free(namestr, MAXNAMELEN);
	}
#endif
}

/*
 * Replay a TX_WRITE ZIL transaction that didn't get committed
 * after a system failure
 */
static int
zvol_replay_write(zvol_state_t *zv, lr_write_t *lr, boolean_t byteswap)
{
	objset_t *os = zv->zv_objset;
	char *data = (char *)(lr + 1);	/* data follows lr_write_t */
	uint64_t offset, length;
	dmu_tx_t *tx;
	int error;

	if (byteswap)
		byteswap_uint64_array(lr, sizeof (*lr));

	offset = lr->lr_offset;
	length = lr->lr_length;

	/* If it's a dmu_sync() block, write the whole block */
	if (lr->lr_common.lrc_reclen == sizeof (lr_write_t)) {
		uint64_t blocksize = BP_GET_LSIZE(&lr->lr_blkptr);
		if (length < blocksize) {
			offset -= offset % blocksize;
			length = blocksize;
		}
	}

	tx = dmu_tx_create(os);
	dmu_tx_hold_write(tx, ZVOL_OBJ, offset, length);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
	} else {
		dmu_write(os, ZVOL_OBJ, offset, length, data, tx);
		dmu_tx_commit(tx);
	}

	return (error);
}

/* ARGSUSED */
static int
zvol_replay_err(zvol_state_t *zv, lr_t *lr, boolean_t byteswap)
{
	return (SET_ERROR(ENOTSUP));
}

/*
 * Callback vectors for replaying records.
 * Only TX_WRITE is needed for zvol.
 */
zil_replay_func_t *zvol_replay_vector[TX_MAX_TYPE] = {
	zvol_replay_err,	/* 0 no such transaction type */
	zvol_replay_err,	/* TX_CREATE */
	zvol_replay_err,	/* TX_MKDIR */
	zvol_replay_err,	/* TX_MKXATTR */
	zvol_replay_err,	/* TX_SYMLINK */
	zvol_replay_err,	/* TX_REMOVE */
	zvol_replay_err,	/* TX_RMDIR */
	zvol_replay_err,	/* TX_LINK */
	zvol_replay_err,	/* TX_RENAME */
	zvol_replay_write,	/* TX_WRITE */
	zvol_replay_err,	/* TX_TRUNCATE */
	zvol_replay_err,	/* TX_SETATTR */
	zvol_replay_err,	/* TX_ACL */
	zvol_replay_err,	/* TX_CREATE_ACL */
	zvol_replay_err,	/* TX_CREATE_ATTR */
	zvol_replay_err,	/* TX_CREATE_ACL_ATTR */
	zvol_replay_err,	/* TX_MKDIR_ACL */
	zvol_replay_err,	/* TX_MKDIR_ATTR */
	zvol_replay_err,	/* TX_MKDIR_ACL_ATTR */
	zvol_replay_err,	/* TX_WRITE2 */
};

static void
zvol_get_done(zgd_t *zgd, int error)
{
	if (zgd->zgd_db)
		dmu_buf_rele(zgd->zgd_db, zgd);

	zfs_range_unlock(zgd->zgd_rl);

	if (error == 0 && zgd->zgd_bp)
		zil_add_block(zgd->zgd_zilog, zgd->zgd_bp);

	kmem_free(zgd, sizeof (zgd_t));
}

/*
 * Get data to generate a TX_WRITE intent log record.
 */
static int
zvol_get_data(void *arg, lr_write_t *lr, char *buf, zio_t *zio)
{
	zvol_state_t *zv = arg;
	objset_t *os = zv->zv_objset;
	uint64_t object = ZVOL_OBJ;
	uint64_t offset = lr->lr_offset;
	uint64_t size = lr->lr_length;	/* length of user data */
	blkptr_t *bp = &lr->lr_blkptr;
	dmu_buf_t *db;
	zgd_t *zgd;
	int error;

	ASSERT(zio != NULL);
	ASSERT(size != 0);

	zgd = kmem_zalloc(sizeof (zgd_t), KM_SLEEP);
	zgd->zgd_zilog = zv->zv_zilog;
	zgd->zgd_rl = zfs_range_lock(&zv->zv_znode, offset, size, RL_READER);

	/*
	 * Write records come in two flavors: immediate and indirect.
	 * For small writes it's cheaper to store the data with the
	 * log record (immediate); for large writes it's cheaper to
	 * sync the data and get a pointer to it (indirect) so that
	 * we don't have to write the data twice.
	 */
	if (buf != NULL) {	/* immediate write */
		error = dmu_read(os, object, offset, size, buf,
		    /*flags*/0);
	} else {
		size = zv->zv_volblocksize;
		offset = P2ALIGN(offset, size);
		error = dmu_buf_hold(os, object, offset, zgd, &db,
		    DMU_READ_NO_PREFETCH);
		if (error == 0) {
			blkptr_t *obp = dmu_buf_get_blkptr(db);
			if (obp) {
				ASSERT(BP_IS_HOLE(bp));
				*bp = *obp;
			}

			zgd->zgd_db = db;
			zgd->zgd_bp = bp;

			ASSERT(db->db_offset == offset);
			ASSERT(db->db_size == size);

			error = dmu_sync(zio, lr->lr_common.lrc_txg,
			    zvol_get_done, zgd);

			if (error == 0)
				return (0);
		}
	}

	zvol_get_done(zgd, error);

	return (error);
}

static int
zvol_iterate_cb(const char *dsname, void *arg)
{
	objset_t *os;
	int err = 0;
	struct zvol_iterate_arg *zvi = arg;

	if (dmu_objset_hold(dsname, FTAG, &os))
		return (0);

	if (dmu_objset_type(os) == DMU_OST_ZVOL)
		err = zvi->zvi_fn(dsname, zvi);
	dmu_objset_rele(os, FTAG);
	return (zvi->zvi_ignore_errors ? 0 : err);
}

void
zvol_setup_iteration(struct zvol_iterate_arg *zvi)
{
	bzero(zvi, sizeof(*zvi));
	mtx_init(&zvi->zvi_mtx, "zvi", NULL, MTX_DEF);
	zvi->zvi_cookie = 1; /* initiator */
}

void
zvol_iterate_wait(struct zvol_iterate_arg *zvi)
{
	mtx_lock(&zvi->zvi_mtx);
	zvi->zvi_cookie--;
	while (zvi->zvi_cookie)
		msleep(zvi, &zvi->zvi_mtx, 0, "zvi", 0);
	mtx_unlock(&zvi->zvi_mtx);
}

static int
zvol_iterate(zvol_iterate_fn_t zvi_fn, char *name_prefix,
    boolean_t ignore_errors, int flags)
{
	struct zvol_iterate_arg zvi;
	int error;

	zvol_setup_iteration(&zvi);
	zvi.zvi_name_prefix = name_prefix;
	zvi.zvi_ignore_errors = ignore_errors;
	zvi.zvi_fn = zvi_fn;

	/* The name prefix given must not be a snapshot. */
	ASSERT3P(strchr(name_prefix, '@'), ==, NULL);
	error = dmu_objset_find(name_prefix, zvol_iterate_cb, &zvi, flags);
	zvol_iterate_wait(&zvi);
	return (error);
}

int
zvol_create_devices(char *name_prefix, boolean_t ignore_errors, int flags)
{
	return (zvol_iterate(zvol_create_device, name_prefix, ignore_errors,
	    flags));
}

int
zvol_destroy_devices(char *name_prefix, boolean_t ignore_errors, int flags)
{
	return (zvol_iterate(zvol_destroy_device, name_prefix, ignore_errors,
	    flags));
}

int
zvol_device_perform(dsl_dataset_t *ds, zvol_device_cb zvdev_cb, char *namestr)
{
	ASSERT0(namestr[0]);
	dsl_dataset_name(ds, namestr);
	return (zvdev_cb(namestr, /*zvi*/NULL));
}

/*
 * Set up a zvol owner instance to the point where it is fully configured
 * and can be set as the owner.  Then set it, and bail if that fails.
 */
static int
zvol_setup(zvol_state_t *zv, objset_t *os, const char *zv_name)
{
	int error;
	uint64_t readonly, volsize;
	dmu_object_info_t doi;

	error = zap_lookup(os, ZVOL_ZAP_OBJ, "size", 8, 1, &volsize);
	if (error)
		return (error);

	error = dsl_prop_get_int_ds(os->os_dsl_dataset, "readonly", &readonly);
	if (error)
		return (error);
	if (!readonly)
		readonly = dmu_objset_is_snapshot(os) ||
		    !spa_writeable(dmu_objset_spa(os));

	error = dmu_object_info(os, ZVOL_OBJ, &doi);
	if (error)
		return (error);

	error = dmu_bonus_hold(os, ZVOL_OBJ, zv, &zv->zv_dbuf);
	if (error)
		return (error);

	ASSERT(os->os_dsl_dataset != NULL);
	ASSERT(!dsl_pool_sync_context(os->os_dsl_dataset->ds_dir->dd_pool));

	zv->zv_objset = os;
	if (readonly != 0)
		zv->zv_flags |= ZVOL_RDONLY;
	zv->zv_volsize = volsize;
	zv->zv_volblocksize = doi.doi_data_block_size;
	(void) strlcpy(zv->zv_name, zv_name, MAXPATHLEN);
	zv->zv_min_bs = DEV_BSHIFT;
	zv->zv_zilog = zil_open(os, zvol_get_data);

	mutex_init(&zv->zv_znode.z_range_lock, NULL, MUTEX_DEFAULT, NULL);
	avl_create(&zv->zv_znode.z_range_avl, zfs_range_compare,
	    sizeof (rl_t), offsetof(rl_t, r_node));
	list_create(&zv->zv_extents, sizeof (zvol_extent_t),
	    offsetof(zvol_extent_t, ze_node));

	/* Attempt to upgrade our hold to ownership. */
	error = dmu_objset_set_owner(os, zv);
	if (error != 0) {
		dmu_buf_rele(zv->zv_dbuf, zv);
		return (error);
	}
	return (0);
}

static int
zvol_first_hold(zvol_state_t *zv, objset_t *os, const char *zv_name)
{
	int error;

	error = zvol_setup(zv, os, zv_name);
	if (error != 0)
		return (error);

	if (spa_writeable(dmu_objset_spa(os))) {
		if (zil_replay_disable)
			zil_destroy(dmu_objset_zil(os), B_FALSE);
		else
			zil_replay(os, zv, zvol_replay_vector);
	}
	atomic_add_32(&zvol_devices, 1);
	dmu_objset_set_user(os, zv);
	return (0);
}

/*
 * Hold the zvol, given its objset, name, and hold count.
 * Returns 0 on success, or the appropriate errno otherwise.
 * On success, returns the zvol_state object actually used in *used_zv.
 * The caller is expected to offer a candidate in *offered_zv, which, if it
 * successfully becomes the objset user/owner, will be NULL'd.
 */
static int
zvol_hold(objset_t *os, const char *zv_name, int count, zvol_state_t **used_zv,
    zvol_state_t **offered_zv)
{
	zvol_state_t *zv;
	int err;

	zv = dmu_objset_get_user(os);
	if (zv != NULL) {
		/* XXX
		 * Even if we used another zvol user, the objset should still
		 * be the same one, since the object for a given objset uses
		 * a winner/loser mechanism.  But it doesn't sometimes???
		 */
		if (zv->zv_objset != os) {
			printf("%s: zv_objset(%p) != os(%p)??\n", __func__,
			    zv->zv_objset, os);
			return (SET_ERROR(ENXIO));
		}
		*used_zv = zv;
		err = 0;
	} else {
		err = zvol_first_hold(*offered_zv, os, zv_name);
		if (err == 0) {
			*used_zv = *offered_zv;
			*offered_zv = NULL;
		}
	}

	if (err == 0)
		(*used_zv)->zv_holds += count;
	return (err);
}

static void
zvol_rele_and_unlock(zvol_state_t **zvp, int count)
{
	zvol_state_t *zv = *zvp;
	objset_t *os = zv->zv_objset;

	ASSERT(MUTEX_HELD(&os->os_user_ptr_lock));
	ASSERT(zv->zv_holds >= count);

	zv->zv_holds -= count;
	if (zv->zv_holds > 0) {
		mutex_exit(&os->os_user_ptr_lock);
		return;
	}

	zil_close(zv->zv_zilog);
	zv->zv_zilog = NULL;
	avl_destroy(&zv->zv_znode.z_range_avl);
	mutex_destroy(&zv->zv_znode.z_range_lock);
	dmu_buf_rele(zv->zv_dbuf, zv);
	zv->zv_dbuf = NULL;
	/* Evict cached data */
	if (dsl_dataset_is_dirty(dmu_objset_ds(zv->zv_objset)) &&
	    !(zv->zv_flags & ZVOL_RDONLY))
		txg_wait_synced(dmu_objset_pool(zv->zv_objset), 0);
	dmu_objset_evict_dbufs(zv->zv_objset);
	dmu_objset_set_user(os, NULL);
	mutex_exit(&os->os_user_ptr_lock);
	atomic_add_32(&zvol_devices, -1);

	/*
	 * This is safe because we unset the user while holding the user
	 * lock, so even if someone is now holding it, they first have to
	 * become the owner before they can set the user.  And we don't free
	 * our user until after calling disown.
	 */
	dmu_objset_disown(os, zv);
	kmem_free(zv, sizeof(*zv));
	*zvp = NULL;
}

int
zvol_open(const char *name, int flag, int count, zvol_state_t **zvp)
{
	int err;
	int holds;
	zvol_state_t *our_zv;
	objset_t *os = NULL;

	/*
	 * Place a hold on the objset using a candidate object, so that if
	 * this is the first holder, it can be upgraded to be the owner.
	 * If this hold ends up not being the owner, it will be released
	 * after all operations are done.
	 */
	*zvp = NULL;
	our_zv = kmem_zalloc(sizeof(*our_zv), KM_SLEEP);

	/* Find and ensure dbuf for objset isn't evicted. */
	err = dmu_objset_hold(name, our_zv, &os);
	if (err != 0) {
		kmem_free(our_zv, sizeof(*our_zv));
		return (err);
	}

	mutex_enter(&os->os_user_ptr_lock);
	/*
	 * Is there a current user?  If so, increment our refcount and use
	 * it.  Otherwise, set up our user before proceeding.
	 */
	err = zvol_hold(os, name, count, zvp, &our_zv);

	if (err == 0) {
		if ((flag & FWRITE) && ((*zvp)->zv_flags & ZVOL_RDONLY))
			err = SET_ERROR(EROFS);
		else if ((*zvp)->zv_flags & ZVOL_EXCL)
			err = SET_ERROR(EBUSY);
#ifdef FEXCL
		else if (flag & FEXCL) {
			if ((*zvp)->zv_holds != 1)
				err = SET_ERROR(EBUSY);
			else
				(*zvp)->zv_flags |= ZVOL_EXCL;
		}
#endif
		zvol_rele_and_unlock(zvp, err ? count : 0);
	} else
		mutex_exit(&os->os_user_ptr_lock);
	if (our_zv != NULL) {
		/* Our zv didn't get used. */
		dmu_objset_rele(os, our_zv);
		kmem_free(our_zv, sizeof(*our_zv));
	}

	return (err);
}

void
zvol_close(zvol_state_t *zv, int count)
{
	objset_t *os;

	os = zv->zv_objset;
	mutex_enter(&os->os_user_ptr_lock);
	if (zv->zv_flags & ZVOL_EXCL)
		zv->zv_flags &= ~ZVOL_EXCL;
	zvol_rele_and_unlock(&zv, count);
}

int
zvol_update_volsize(objset_t *os, uint64_t volsize)
{
	dmu_tx_t *tx;
	int error;

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, ZVOL_ZAP_OBJ, TRUE, NULL);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		return (error);
	}

	error = zap_update(os, ZVOL_ZAP_OBJ, "size", 8, 1,
	    &volsize, tx);
	dmu_tx_commit(tx);

	if (error == 0)
		error = dmu_free_long_range(os,
		    ZVOL_OBJ, volsize, DMU_OBJECT_END);
	return (error);
}

int
zvol_set_volsize(const char *name, major_t maj, uint64_t volsize)
{
	zvol_state_t *zv;
	objset_t *os;
	int error;
	dmu_object_info_t doi;
	uint64_t old_volsize = 0ULL;
	uint64_t readonly;

	error = zvol_open(name, FWRITE, /*count*/1, &zv);
	if (error)
		return (error);
	os = zv->zv_objset;

	error = dmu_object_info(os, ZVOL_OBJ, &doi);
	if (error == 0)
		error = zvol_check_volsize(volsize, doi.doi_data_block_size);
	if (error)
		goto out;

	if (zv->zv_flags & ZVOL_RDONLY) {
		error = SET_ERROR(EROFS);
		goto out;
	}

	error = zvol_update_volsize(os, volsize);
	/*
	 * Reinitialize the dump area to the new size. If we
	 * failed to resize the dump area then restore it back to
	 * its original size.
	 */
	if (error == 0) {
		error = zvol_dumpify_size_change(zv, os, volsize);
		if (error == 0) {
			zv->zv_volsize = volsize;
			zvol_size_changed(zv);
		}
	}

	/*
	 * Generate a LUN expansion event.
	 */
	if (zv && error == 0)
		zvol_generate_lun_expansion_event(zv);

out:
	zvol_close(zv, /*count*/1);
	return (error);
}

ssize_t zvol_immediate_write_sz = 32768;
/*
 * handles synchronous writes using TX_WRITE ZIL transactions.
 *
 * We store data in the log buffers if it's small enough.
 * Otherwise we will later flush the data out via dmu_sync().
 */
static void
zvol_log_write(zvol_state_t *zv, dmu_tx_t *tx, offset_t off, ssize_t resid,
    boolean_t sync)
{
	uint32_t blocksize = zv->zv_volblocksize;
	zilog_t *zilog = zv->zv_zilog;
	boolean_t slogging;
	ssize_t immediate_write_sz;

	if (zil_replaying(zilog, tx))
		return;

	immediate_write_sz = (zilog->zl_logbias == ZFS_LOGBIAS_THROUGHPUT)
	    ? 0 : zvol_immediate_write_sz;

	slogging = spa_has_slogs(zilog->zl_spa) &&
	    (zilog->zl_logbias == ZFS_LOGBIAS_LATENCY);

	while (resid) {
		itx_t *itx;
		lr_write_t *lr;
		ssize_t len;
		itx_wr_state_t write_state;

		/*
		 * Unlike zfs_log_write() we can be called with
		 * upto DMU_MAX_ACCESS/2 (5MB) writes.
		 */
		if (blocksize > immediate_write_sz && !slogging &&
		    resid >= blocksize && off % blocksize == 0) {
			write_state = WR_INDIRECT; /* uses dmu_sync */
			len = blocksize;
		} else if (sync) {
			write_state = WR_COPIED;
			len = MIN(ZIL_MAX_LOG_DATA, resid);
		} else {
			write_state = WR_NEED_COPY;
			len = MIN(ZIL_MAX_LOG_DATA, resid);
		}

		itx = zil_itx_create(TX_WRITE, sizeof (*lr) +
		    (write_state == WR_COPIED ? len : 0));
		lr = (lr_write_t *)&itx->itx_lr;
		if (write_state == WR_COPIED && dmu_read(zv->zv_objset,
		    ZVOL_OBJ, off, len, lr + 1, /*flags*/0) != 0) {
			zil_itx_destroy(itx);
			itx = zil_itx_create(TX_WRITE, sizeof (*lr));
			lr = (lr_write_t *)&itx->itx_lr;
			write_state = WR_NEED_COPY;
		}

		itx->itx_wr_state = write_state;
		if (write_state == WR_NEED_COPY)
			itx->itx_sod += len;
		lr->lr_foid = ZVOL_OBJ;
		lr->lr_offset = off;
		lr->lr_length = len;
		lr->lr_blkoff = 0;
		BP_ZERO(&lr->lr_blkptr);

		itx->itx_private = zv;
		itx->itx_sync = sync;

		zil_itx_assign(zilog, itx, tx);

		off += len;
		resid -= len;
	}
}

static void
zvol_dmu_buf_set_transfer_write(dmu_buf_set_t *buf_set)
{
	zvol_dmu_state_t *zds = (zvol_dmu_state_t *)buf_set->dmu_ctx;
	zvol_state_t *zv = zds->zv;
	boolean_t sync = (zv->zv_objset->os_sync == ZFS_SYNC_ALWAYS);
	dmu_tx_t *tx = DMU_BUF_SET_TX(buf_set);

	dmu_buf_set_transfer_write(buf_set);

	/* Log this write. */
	if ((zv->zv_flags & ZVOL_WCE) == 0 || sync)
		zvol_log_write(zv, tx, buf_set->dn_start, buf_set->size, sync);
	dmu_tx_commit(tx);
}

void
zvol_dmu_done(dmu_context_t *dmu_ctx)
{
	zvol_dmu_state_t *zds = (zvol_dmu_state_t *)dmu_ctx;

	if ((dmu_ctx->flags & DMU_CTX_FLAG_READ) == 0 && 
	    (zds->zv->zv_objset->os_sync == ZFS_SYNC_ALWAYS))
		zil_commit(zds->zv->zv_zilog, ZVOL_OBJ);
	if (dmu_ctx->completed_size < dmu_ctx->size &&
	    dmu_ctx->dn_offset > zds->zv->zv_volsize)
		dmu_ctx->err = zio_worst_error(dmu_ctx->err, SET_ERROR(EINVAL));

	zfs_range_unlock(zds->rl);
}

int
zvol_dmu_context_init(zvol_dmu_state_t *zds, void *data, uint64_t off,
    uint64_t io_size, uint32_t dmu_flags, dmu_context_callback_t done_cb)
{
	zvol_state_t *zv = zds->zv;
	boolean_t reader = (dmu_flags & DMU_CTX_FLAG_READ) != 0;
	int error;

	ASSERT(zv->zv_objset != NULL);

	if (reader)
		dmu_flags |= DMU_CTX_FLAG_PREFETCH;
	else if (zv->zv_flags & ZVOL_RDONLY)
		return (SET_ERROR(EIO));

	/* Reject I/Os that don't fall within the volume. */
	if (io_size > 0 && off >= zv->zv_volsize)
		return (SET_ERROR(EIO));

	/* Truncate I/Os to the end of the volume, if needed. */
	io_size = MIN(io_size, zv->zv_volsize - off);

	error = dmu_context_init(&zds->dmu_ctx, /*dnode*/NULL, zv->zv_objset,
	    ZVOL_OBJ, off, io_size, data, FTAG, dmu_flags);
	if (error)
		return (error);
	/* Override the writer case to log the writes. */
	if (!reader)
		dmu_context_set_buf_set_transfer_cb(&zds->dmu_ctx,
		    zvol_dmu_buf_set_transfer_write);
	dmu_context_set_context_cb(&zds->dmu_ctx, done_cb);
	zds->rl = zfs_range_lock(&zds->zv->zv_znode, off, io_size,
	    reader ? RL_READER : RL_WRITER);

	return (error);
}

void
zvol_dmu_issue(zvol_dmu_state_t *zds)
{
	/* Errors are reported to the done callback via dmu_ctx->err. */
	(void) dmu_issue(&zds->dmu_ctx);
	dmu_context_rele(&zds->dmu_ctx);
}

int
zvol_dmu_uio(zvol_dmu_state_t *zds, uio_t *uio, uint32_t dmu_flags)
{
	int err;

	if (zds->zv == NULL)
		return (SET_ERROR(ENXIO));

	if (zds->zv->zv_flags & ZVOL_DUMPIFIED)
		return (zvol_physio(zds->zv, uio));

	/* Don't allow I/Os that are not within the volume. */
	if (uio->uio_resid > 0 &&
	    (uio->uio_loffset < 0 || uio->uio_loffset >= zds->zv->zv_volsize))
		return (SET_ERROR(EIO));

	err = zvol_dmu_context_init(zds, uio, uio->uio_loffset,
	    uio->uio_resid, dmu_flags|DMU_CTX_FLAG_UIO, zvol_dmu_done);
	if (err)
		return (err);
	zvol_dmu_issue(zds);
	return (zds->dmu_ctx.err);
}

int
zvol_busy(void)
{
	return (zvol_devices != 0);
}

void
zvol_init(void)
{
	VERIFY(ddi_soft_state_init(&zfsdev_state, sizeof (zfs_soft_state_t),
	    1) == 0);
	mutex_init(&zfsdev_state_lock, NULL, MUTEX_DEFAULT, NULL);
	zvol_os_init();
}

void
zvol_fini(void)
{
	mutex_destroy(&zfsdev_state_lock);
	ddi_soft_state_fini(&zfsdev_state);
	zvol_os_fini();
}
