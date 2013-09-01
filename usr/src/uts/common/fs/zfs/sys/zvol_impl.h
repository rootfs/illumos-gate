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
 * Copyright (c) 2012 Spectra Logic Corporation.  All rights reserved.
 */

#ifndef	_SYS_ZVOL_IMPL_H
#define	_SYS_ZVOL_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

/* zvol specific flags */
#define	ZVOL_RDONLY	0x1
#define	ZVOL_DUMPIFIED	0x2
#define	ZVOL_EXCL	0x4
#define	ZVOL_WCE	0x8

typedef struct zvol_extent {
	list_node_t	ze_node;
	dva_t		ze_dva;		/* dva associated with this extent */
	uint64_t	ze_nblks;	/* number of blocks in extent */
} zvol_extent_t;

typedef struct zvol_state {
	char		zv_name[MAXPATHLEN]; /* pool/dd name */
	uint64_t	zv_volsize;	/* amount of space we advertise */
	uint64_t	zv_volblocksize; /* volume block size */
	uint8_t		zv_min_bs;	/* minimum addressable block shift */
	uint8_t		zv_flags;	/* readonly, dumpified, etc. */
	objset_t	*zv_objset;	/* objset handle */
	int		zv_holds;	/* Number of holds on this instance */
	zilog_t		*zv_zilog;	/* ZIL handle */
	list_t		zv_extents;	/* List of extents for dump */
	znode_t		zv_znode;	/* for range locking */
	dmu_buf_t	*zv_dbuf;	/* bonus handle */
	void		*zv_private;	/* Current OS "owner" */
} zvol_state_t;

typedef struct zvol_dmu_state {
	/*
	 * The DMU context associated with this DMU state.  Note that this
	 * must be the first entry in order for the callback to be able to
	 * discover the zvol_dmu_state_t.
	 */
	dmu_context_t dmu_ctx;
	zvol_state_t *zv;
	rl_t *rl;
} zvol_dmu_state_t;

typedef int (*zvol_iterate_fn_t)(const char *, void *);
struct zvol_iterate_arg {
	zvol_iterate_fn_t	zvi_fn;
	const char		*zvi_name_prefix;
	boolean_t		zvi_ignore_errors;
	boolean_t		zvi_recursive;
	int			zvi_cookie;
	struct mtx		zvi_mtx;
};
void zvol_iterate_wait(struct zvol_iterate_arg *zvi);
void zvol_setup_iteration(struct zvol_iterate_arg *zvi);

typedef int (*zvol_device_cb)(const char *name, void *data);

int zvol_open(const char *name, int flag, int count, zvol_state_t **zvp);
void zvol_close(zvol_state_t *zv, int count);

int zvol_physio(zvol_state_t *zv, uio_t *uio);
void zvol_generate_lun_expansion_event(zvol_state_t *zv);
int zvol_dmu_context_init(zvol_dmu_state_t *zds, void *data, uint64_t off,
    uint64_t io_size, uint32_t dmu_flags, dmu_context_callback_t done_cb);
void zvol_dmu_issue(zvol_dmu_state_t *zds);
int zvol_dmu_uio(zvol_dmu_state_t *zds, uio_t *uio, uint32_t dmu_flags);
void zvol_dmu_done(dmu_context_t *dmu_ctx);
int zvol_device_perform(dsl_dataset_t *ds, zvol_device_cb zvdev_cb,
    char *namestr);

void zvol_size_changed(zvol_state_t *zv);
void zvol_os_init(void);
void zvol_os_fini(void);

extern zil_replay_func_t *zvol_replay_vector[TX_MAX_TYPE];
extern uint32_t zvol_minors;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ZVOL_IMPL_H */
