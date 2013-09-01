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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_ZVOL_H
#define	_SYS_ZVOL_H

#include <sys/zfs_context.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	ZVOL_OBJ		1ULL
#define	ZVOL_ZAP_OBJ		2ULL

#ifdef _KERNEL
extern int zvol_check_volsize(uint64_t volsize, uint64_t blocksize);
extern int zvol_check_volblocksize(uint64_t volblocksize);
extern int zvol_namecheck(const char *name);
extern int zvol_get_stats(objset_t *os, nvlist_t *nv);
extern void zvol_create_cb(objset_t *os, void *arg, cred_t *cr, dmu_tx_t *tx);
extern int zvol_create_device(const char *zv_name, void *arg);
extern int zvol_create_from_objset(objset_t *os, const char *snapname);
extern int zvol_destroy_device(const char *zv_name, void *arg);
extern int zvol_create_devices(char *name_prefix, boolean_t recursive,
    boolean_t ignore_errors);
extern int zvol_destroy_devices(char *name_prefix, boolean_t recursive,
    boolean_t ignore_errors);
extern void zvol_rename_devices(const char *oldname, const char *newname);
extern int zvol_set_volsize(const char *, major_t, uint64_t);

extern void zvol_rename_cleanup(dsl_dir_rename_arg_t *);
extern void zvol_rename_snapshot_cleanup(dsl_dataset_rename_snapshot_arg_t *);
extern int zvol_create_init(dmu_objset_create_arg_t *);
extern int zvol_snapshot_init(dsl_dataset_snapshot_arg_t *);
extern int zvol_promote_init(dsl_dataset_promote_arg_t *);
extern int zvol_clone_init(dmu_objset_clone_arg_t *);
extern int zvol_destroy_snaps_init(dmu_snapshots_destroy_arg_t *);
extern int zvol_destroy_head_init(dsl_destroy_head_arg_t *);

#ifdef sun
extern int zvol_open(dev_t *devp, int flag, int otyp, cred_t *cr);
extern int zvol_dump(dev_t dev, caddr_t addr, daddr_t offset, int nblocks);
extern int zvol_close(dev_t dev, int flag, int otyp, cred_t *cr);
extern int zvol_strategy(buf_t *bp);
extern int zvol_read(dev_t dev, uio_t *uiop, cred_t *cr);
extern int zvol_write(dev_t dev, uio_t *uiop, cred_t *cr);
extern int zvol_aread(dev_t dev, struct aio_req *aio, cred_t *cr);
extern int zvol_awrite(dev_t dev, struct aio_req *aio, cred_t *cr);
#endif	/* sun */
extern int zvol_ioctl(dev_t dev, int cmd, intptr_t arg, int flag, cred_t *cr,
    int *rvalp);
extern int zvol_busy(void);
extern void zvol_init(void);
extern void zvol_fini(void);

#ifdef sun
extern int zvol_get_volume_params(minor_t minor, uint64_t *blksize,
    uint64_t *max_xfer_len, void **minor_hdl, void **objset_hdl, void **zil_hdl,
    void **rl_hdl, void **bonus_hdl);
extern uint64_t zvol_get_volume_size(void *minor_hdl);
extern int zvol_get_volume_wce(void *minor_hdl);
extern void zvol_log_write_minor(void *minor_hdl, dmu_tx_t *tx, offset_t off,
    ssize_t resid, boolean_t sync);
#endif	/* sun */

#ifdef __FreeBSD__
extern int zvol_create_minors(const char *name);
extern void zvol_rename_minors(const char *oldname, const char *newname);
#endif

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ZVOL_H */
