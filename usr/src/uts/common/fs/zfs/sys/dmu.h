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
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright (c) 2011-2012 Spectra Logic Corporation.  All rights reserved.
 * Copyright 2011 Nexenta Systems, Inc. All rights reserved.
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

/* Portions Copyright 2010 Robert Milkowski */

#ifndef	_SYS_DMU_H
#define	_SYS_DMU_H

/**
 * \file dmu.h
 * \brief This file describes the interface that the DMU provides for its
 * consumers.
 *
 * The DMU also interacts with the SPA.  That interface is described in
 * dmu_spa.h.
 */

#include <sys/zfs_context.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/cred.h>
#include <sys/time.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct uio;
struct xuio;
struct page;
struct vnode;
struct spa;
struct zilog;
struct zio;
struct blkptr;
struct zap_cursor;
struct dsl_dataset;
struct dsl_pool;
struct dnode;
struct drr_begin;
struct drr_end;
struct zbookmark;
struct spa;
struct nvlist;
struct arc_buf;
struct zio_prop;
struct sa_handle;
struct file;

typedef struct objset objset_t;
typedef struct dmu_tx dmu_tx_t;
typedef struct dsl_dir dsl_dir_t;

typedef enum dmu_object_byteswap {
	DMU_BSWAP_UINT8,
	DMU_BSWAP_UINT16,
	DMU_BSWAP_UINT32,
	DMU_BSWAP_UINT64,
	DMU_BSWAP_ZAP,
	DMU_BSWAP_DNODE,
	DMU_BSWAP_OBJSET,
	DMU_BSWAP_ZNODE,
	DMU_BSWAP_OLDACL,
	DMU_BSWAP_ACL,
	/*
	 * Allocating a new byteswap type number makes the on-disk format
	 * incompatible with any other format that uses the same number.
	 *
	 * Data can usually be structured to work with one of the
	 * DMU_BSWAP_UINT* or DMU_BSWAP_ZAP types.
	 */
	DMU_BSWAP_NUMFUNCS
} dmu_object_byteswap_t;

#define	DMU_OT_NEWTYPE 0x80
#define	DMU_OT_METADATA 0x40
#define	DMU_OT_BYTESWAP_MASK 0x3f

/*
 * Defines a uint8_t object type. Object types specify if the data
 * in the object is metadata (boolean) and how to byteswap the data
 * (dmu_object_byteswap_t).
 */
#define	DMU_OT(byteswap, metadata) \
	(DMU_OT_NEWTYPE | \
	((metadata) ? DMU_OT_METADATA : 0) | \
	((byteswap) & DMU_OT_BYTESWAP_MASK))

#define	DMU_OT_IS_VALID(ot) (((ot) & DMU_OT_NEWTYPE) ? \
	((ot) & DMU_OT_BYTESWAP_MASK) < DMU_BSWAP_NUMFUNCS : \
	(ot) < DMU_OT_NUMTYPES)

#define	DMU_OT_IS_METADATA(ot) (((ot) & DMU_OT_NEWTYPE) ? \
	((ot) & DMU_OT_METADATA) : \
	dmu_ot[(ot)].ot_metadata)

#define	DMU_OT_BYTESWAP(ot) (((ot) & DMU_OT_NEWTYPE) ? \
	((ot) & DMU_OT_BYTESWAP_MASK) : \
	dmu_ot[(ot)].ot_byteswap)

typedef enum dmu_object_type {
	DMU_OT_NONE,
	/* general: */
	DMU_OT_OBJECT_DIRECTORY,	/**< ZAP */
	DMU_OT_OBJECT_ARRAY,		/**< UINT64 */
	DMU_OT_PACKED_NVLIST,		/**< UINT8 (XDR by nvlist_pack/unpack)*/
	DMU_OT_PACKED_NVLIST_SIZE,	/**< UINT64 */
	DMU_OT_BPOBJ,			/**< UINT64 */
	DMU_OT_BPOBJ_HDR,		/**< UINT64 */
	/* spa: */
	DMU_OT_SPACE_MAP_HEADER,	/**< UINT64 */
	DMU_OT_SPACE_MAP,		/**< UINT64 */
	/* zil: */
	DMU_OT_INTENT_LOG,		/**< UINT64 */
	/* dmu: */
	DMU_OT_DNODE,			/**< DNODE */
	DMU_OT_OBJSET,			/**< OBJSET */
	/* dsl: */
	DMU_OT_DSL_DIR,			/**< UINT64 */
	DMU_OT_DSL_DIR_CHILD_MAP,	/**< ZAP */
	DMU_OT_DSL_DS_SNAP_MAP,		/**< ZAP */
	DMU_OT_DSL_PROPS,		/**< ZAP */
	DMU_OT_DSL_DATASET,		/**< UINT64 */
	/* zpl: */
	DMU_OT_ZNODE,			/**< ZNODE */
	DMU_OT_OLDACL,			/**< Old ACL */
	DMU_OT_PLAIN_FILE_CONTENTS,	/**< UINT8 */
	DMU_OT_DIRECTORY_CONTENTS,	/**< ZAP */
	DMU_OT_MASTER_NODE,		/**< ZAP */
	DMU_OT_UNLINKED_SET,		/**< ZAP */
	/* zvol: */
	DMU_OT_ZVOL,			/**< UINT8 */
	DMU_OT_ZVOL_PROP,		/**< ZAP */
	/* other; for testing only! */
	DMU_OT_PLAIN_OTHER,		/**< UINT8 */
	DMU_OT_UINT64_OTHER,		/**< UINT64 */
	DMU_OT_ZAP_OTHER,		/**< ZAP */
	/* new object types: */
	DMU_OT_ERROR_LOG,		/**< ZAP */
	DMU_OT_SPA_HISTORY,		/**< UINT8 */
	DMU_OT_SPA_HISTORY_OFFSETS,	/**< spa_his_phys_t */
	DMU_OT_POOL_PROPS,		/**< ZAP */
	DMU_OT_DSL_PERMS,		/**< ZAP */
	DMU_OT_ACL,			/**< ACL */
	DMU_OT_SYSACL,			/**< SYSACL */
	DMU_OT_FUID,			/**< FUID table (Packed NVLIST UINT8) */
	DMU_OT_FUID_SIZE,		/**< FUID table size UINT64 */
	DMU_OT_NEXT_CLONES,		/**< ZAP */
	DMU_OT_SCAN_QUEUE,		/**< ZAP */
	DMU_OT_USERGROUP_USED,		/**< ZAP */
	DMU_OT_USERGROUP_QUOTA,		/**< ZAP */
	DMU_OT_USERREFS,		/**< ZAP */
	DMU_OT_DDT_ZAP,			/**< ZAP */
	DMU_OT_DDT_STATS,		/**< ZAP */
	DMU_OT_SA,			/**< System attr */
	DMU_OT_SA_MASTER_NODE,		/**< ZAP */
	DMU_OT_SA_ATTR_REGISTRATION,	/**< ZAP */
	DMU_OT_SA_ATTR_LAYOUTS,		/**< ZAP */
	DMU_OT_SCAN_XLATE,		/**< ZAP */
	DMU_OT_DEDUP,			/**<fake dedup BP from ddt_bp_create()*/
	DMU_OT_DEADLIST,		/**< ZAP */
	DMU_OT_DEADLIST_HDR,		/**< UINT64 */
	DMU_OT_DSL_CLONES,		/**< ZAP */
	DMU_OT_BPOBJ_SUBOBJ,		/**< UINT64 */
	/*
	 * Do not allocate new object types here. Doing so makes the on-disk
	 * format incompatible with any other format that uses the same object
	 * type number.
	 *
	 * When creating an object which does not have one of the above types
	 * use the DMU_OTN_* type with the correct byteswap and metadata
	 * values.
	 *
	 * The DMU_OTN_* types do not have entries in the dmu_ot table,
	 * use the DMU_OT_IS_METDATA() and DMU_OT_BYTESWAP() macros instead
	 * of indexing into dmu_ot directly (this works for both DMU_OT_* types
	 * and DMU_OTN_* types).
	 */
	DMU_OT_NUMTYPES,

	/*
	 * Names for valid types declared with DMU_OT().
	 */
	DMU_OTN_UINT8_DATA = DMU_OT(DMU_BSWAP_UINT8, B_FALSE),
	DMU_OTN_UINT8_METADATA = DMU_OT(DMU_BSWAP_UINT8, B_TRUE),
	DMU_OTN_UINT16_DATA = DMU_OT(DMU_BSWAP_UINT16, B_FALSE),
	DMU_OTN_UINT16_METADATA = DMU_OT(DMU_BSWAP_UINT16, B_TRUE),
	DMU_OTN_UINT32_DATA = DMU_OT(DMU_BSWAP_UINT32, B_FALSE),
	DMU_OTN_UINT32_METADATA = DMU_OT(DMU_BSWAP_UINT32, B_TRUE),
	DMU_OTN_UINT64_DATA = DMU_OT(DMU_BSWAP_UINT64, B_FALSE),
	DMU_OTN_UINT64_METADATA = DMU_OT(DMU_BSWAP_UINT64, B_TRUE),
	DMU_OTN_ZAP_DATA = DMU_OT(DMU_BSWAP_ZAP, B_FALSE),
	DMU_OTN_ZAP_METADATA = DMU_OT(DMU_BSWAP_ZAP, B_TRUE),
} dmu_object_type_t;

typedef enum dmu_objset_type {
	DMU_OST_NONE,
	DMU_OST_META,
	DMU_OST_ZFS,
	DMU_OST_ZVOL,
	DMU_OST_OTHER,			/** For testing only! */
	DMU_OST_ANY,			/** Be careful! */
	DMU_OST_NUMTYPES
} dmu_objset_type_t;

void byteswap_uint64_array(void *buf, size_t size);
void byteswap_uint32_array(void *buf, size_t size);
void byteswap_uint16_array(void *buf, size_t size);
void byteswap_uint8_array(void *buf, size_t size);
void zap_byteswap(void *buf, size_t size);
void zfs_oldacl_byteswap(void *buf, size_t size);
void zfs_acl_byteswap(void *buf, size_t size);
void zfs_znode_byteswap(void *buf, size_t size);

#define	DS_FIND_SNAPSHOTS	(1<<0)
#define	DS_FIND_CHILDREN	(1<<1)

/**
 * The maximum number of bytes that can be accessed as part of one
 * operation, including metadata.
 */
#define	DMU_MAX_ACCESS (10<<20) /* 10MB */
#define	DMU_MAX_DELETEBLKCNT (20480) /* ~5MB of indirect blocks */

#define	DMU_USERUSED_OBJECT	(-1ULL)
#define	DMU_GROUPUSED_OBJECT	(-2ULL)
#define	DMU_DEADLIST_OBJECT	(-3ULL)

/**
 * \brief Artificial blkid for bonus blocks
 */
#define	DMU_BONUS_BLKID		(ULLONG_MAX)
/**
 * \brief Artificial blkid for spill blocks
 */
#define	DMU_SPILL_BLKID		(ULLONG_MAX - 1)
/*
 * Public routines to create, destroy, open, and close objsets.
 */
int dmu_objset_hold(const char *name, void *tag, objset_t **osp);
int dmu_objset_own(const char *name, dmu_objset_type_t type,
    boolean_t readonly, void *tag, objset_t **osp);
void dmu_objset_rele(objset_t *os, void *tag);
void dmu_objset_disown(objset_t *os, void *tag);
int dmu_objset_open_ds(struct dsl_dataset *ds, objset_t **osp);

int dmu_objset_evict_dbufs(objset_t *os);
int dmu_objset_create(const char *name, dmu_objset_type_t type, uint64_t flags,
    void (*func)(objset_t *os, void *arg, cred_t *cr, dmu_tx_t *tx), void *arg);
int dmu_objset_clone(const char *name, struct dsl_dataset *clone_origin,
    uint64_t flags);
int dmu_objset_destroy(const char *name, boolean_t defer);
int dmu_get_recursive_snaps_nvl(const char *fsname, const char *snapname,
    struct nvlist *snaps);
int dmu_snapshots_destroy_nvl(struct nvlist *snaps, boolean_t defer, char *);
int dmu_objset_snapshot(char *fsname, char *snapname, char *tag,
    struct nvlist *props, boolean_t recursive, boolean_t temporary, int fd);
int dmu_objset_rename(const char *name, const char *newname,
    boolean_t recursive);
int dmu_objset_find(const char *name, int func(const char *, void *), void *arg,
    int flags);
void dmu_objset_byteswap(void *buf, size_t size);

typedef struct dmu_buf {
	uint64_t db_object;		/**<object that this buffer is part of*/
	uint64_t db_offset;		/**< byte offset in this object */
	uint64_t db_size;		/**< size of buffer in bytes */
	void *db_data;			/**< data in buffer */
} dmu_buf_t;

/**
 * \brief These structures are for DMU consumers that want async
 * callbacks.
 */
struct dmu_context;
struct dmu_buf_set;
struct zio;
typedef void (*dmu_context_callback_t)(struct dmu_context *);
typedef void (*dmu_buf_set_callback_t)(struct dmu_buf_set *);
typedef void (*dmu_buf_transfer_callback_t)(struct dmu_buf_set *, dmu_buf_t *,
    uint64_t, uint64_t);

typedef struct dmu_context {

	/** The primary data associated with this context. */
	uint64_t size;		/**< Requested total I/O size. */
	uint64_t resid;		/**< Remaining bytes to process. */
	uint64_t dn_start;	/**< Starting block offset into the dnode. */
	uint64_t dn_offset;	/**< Current block offset. */
	dmu_tx_t *tx;		/**< Caller's transaction, if specified. */
	void *data_buf;		/**< UIO or char pointer */

	/** The dnode held in association with this context. */
	struct dnode *dn;
	objset_t *os;		/**< Object set associated with the dnode. */
	uint64_t object;	/**< Object ID associated with the dnode. */

	/** Number of buffer sets left to complete. */
	int holds;

	/** The tag used for this context. */
	void *tag;

	/** The callback to call once an I/O completes entirely. */
	dmu_context_callback_t context_cb;

	/** The callback to call to transfer a buffer set. */
	dmu_buf_set_callback_t buf_set_transfer_cb;

	/** The callback to call to transfer a buffer. */
	dmu_buf_transfer_callback_t buf_transfer_cb;

	/**
	 * The callback to call to move a specific block's contents.  This
	 * is normally only set by dmu_context_init().
	 */
	dmu_buf_transfer_callback_t move_cb;

	/** Total number of bytes transferred. */
	uint64_t completed_size;

	/** Flags for this DMU context. */
	uint32_t flags;
#define	DMU_CTX_FLAG_READ	(1 << 1)
#define	DMU_CTX_FLAG_UIO	(1 << 2)
#define	DMU_CTX_FLAG_PREFETCH	(1 << 3)
#define	DMU_CTX_FLAG_NO_HOLD	(1 << 4)
#define	DMU_CTX_FLAG_SUN_PAGES	(1 << 5)
#define	DMU_CTX_FLAG_NOFILL	(1 << 6)
#define	DMU_CTX_FLAG_ASYNC	(1 << 7)

#define	DMU_CTX_WRITER_FLAGS	(DMU_CTX_FLAG_SUN_PAGES|DMU_CTX_FLAG_NOFILL)
#define	DMU_CTX_READER_FLAGS	(DMU_CTX_FLAG_PREFETCH)

#define	DMU_CTX_BUF_IS_CHAR(dmu_ctx) \
	(((dmu_ctx)->flags & (DMU_CTX_FLAG_UIO|DMU_CTX_FLAG_SUN_PAGES)) == 0)

	/** The number of errors that occurred. */
	int err;

} dmu_context_t;

typedef struct dmu_buf_set {

	/** The DMU context that this buffer set is associated with. */
	dmu_context_t *dmu_ctx;

	/** Number of dmu_bufs associated with this context. */
	int count;

	/** Length of dbp; only used to free the correct size. */
	int dbp_length;

	/** Number of dmu_bufs left to complete. */
	int holds;

	/** The starting offset, relative to the associated dnode. */
	uint64_t dn_start;
	/** The size of the I/O. */
	uint64_t size;
	/** The amount of data remaining to process for this buffer set. */
	uint64_t resid;

	/** For writes only, if the context doesn't have a transaction. */
	dmu_tx_t *tx;
#define	DMU_BUF_SET_TX(buf_set) \
	((buf_set)->dmu_ctx->tx ? (buf_set)->dmu_ctx->tx : (buf_set)->tx)

	/** The number of errors that occurred. */
	int err;

	/** The ZIO associated with this context. */
	struct zio *zio;

	/** The set of buffers themselves. */
	struct dmu_buf *dbp[0];

} dmu_buf_set_t;

void dmu_buf_set_rele(dmu_buf_set_t *buf_set, boolean_t err);
int dmu_context_init(dmu_context_t *dmu_ctx, struct dnode *dn, objset_t *os,
    uint64_t object, uint64_t offset, uint64_t size, void *data_buf, void *tag,
    uint32_t flags);
void dmu_context_seek(dmu_context_t *dmu_ctx, uint64_t offset, uint64_t size,
    void *data_buf);
void dmu_context_rele(dmu_context_t *dmu_ctx);
void dmu_buf_set_transfer(dmu_buf_set_t *buf_set);
void dmu_buf_set_transfer_write(dmu_buf_set_t *buf_set);

/* Optional context setters; use after calling dmu_context_init*(). */
static inline void
dmu_context_set_context_cb(dmu_context_t *ctx, dmu_context_callback_t cb)
{
	ctx->context_cb = cb;
}
static inline void
dmu_context_set_buf_set_transfer_cb(dmu_context_t *ctx,
    dmu_buf_set_callback_t cb)
{
	ctx->buf_set_transfer_cb = cb;
}
static inline void
dmu_context_set_buf_transfer_cb(dmu_context_t *ctx,
    dmu_buf_transfer_callback_t cb)
{
	ctx->buf_transfer_cb = cb;
}
static inline void
dmu_context_set_dmu_tx(dmu_context_t *ctx, dmu_tx_t *tx)
{
	ASSERT(tx != NULL && ((ctx->flags & DMU_CTX_FLAG_READ) == 0));
	dmu_context_set_buf_set_transfer_cb(ctx, dmu_buf_set_transfer);
	ctx->tx = tx;
}

/* DMU thread context handlers. */
int dmu_thread_context_create(void);
void dmu_thread_context_process(void);
void dmu_thread_context_destroy(void *);

struct dmu_buf_user;

typedef void dmu_buf_evict_func_t(struct dmu_buf_user *);

/**
 * The DMU buffer user object is used to allow private data to be
 * associated with a dbuf for the duration of its lifetime.  This private
 * data must include a dmu_buf_user_t as its first object, which is passed
 * into the DMU user data API and can be attached to a dbuf.  Clients can
 * regain access to their private data structure with a cast.
 *
 * DMU buffer users can be notified via a callback when their associated
 * dbuf has been evicted.  This is typically used to free the user's
 * private data.  The eviction callback is executed without the dbuf
 * mutex held or any other type of mechanism to guarantee that the
 * dbuf is still available.  For this reason, users must assume the dbuf
 * has already been freed and not reference the dbuf from the callback
 * context.
 *
 * Users requestion "immediate eviction" are notified as soon as the dbuf
 * is only referenced by dirty records (dirties == holds).  Otherwise the
 * eviction callback occurs after the last reference to the dbuf is dropped.
 *
 * Eviction Callback Processing
 * ============================
 * In any context where a dbuf reference drop may trigger an eviction, an
 * eviction queue object must be provided.  This queue must then be
 * processed while not holding any dbuf locks.  In this way, the user can
 * perform any work needed in their eviction function without fear of
 * lock order reversals.
 */
typedef struct dmu_buf_user {
	/**
	 * This instance's link in the eviction queue.  Set when the buffer
	 * has evicted and the callback needs to be called.
	 */
	list_node_t evict_queue_link;
	/** This instance's eviction function pointer. */
	dmu_buf_evict_func_t *evict_func;
} dmu_buf_user_t;

/**
 * \brief Initialization routine for dmu_buf_user_t instances.
 *
 * \param dbu			Dbuf user instance to initialize.
 * \param evict_func		Eviction function pointer to use.
 * \param user_data_ptr_ptr	Pointer to pointer to update.
 *
 * \note This function should only be called once on a given object.  To
 *	 help enforce this, dbu should already be zeroed on entry.
 */
static inline void
dmu_buf_init_user(dmu_buf_user_t *dbu, dmu_buf_evict_func_t *evict_func)
{
	ASSERT(dbu->evict_func == NULL);
	ASSERT(!list_link_active(&dbu->evict_queue_link));
	dbu->evict_func = evict_func;
}

/** DMU buffer user eviction routines. */
static inline void
dmu_buf_create_user_evict_list(list_t *evict_list_p)
{
	list_create(evict_list_p, sizeof(dmu_buf_user_t),
	    offsetof(dmu_buf_user_t, evict_queue_link));
}
static inline void
dmu_buf_process_user_evicts(list_t *evict_list_p)
{
	dmu_buf_user_t *dbu, *next;

	for (dbu = (dmu_buf_user_t *)list_head(evict_list_p); dbu != NULL;
	    dbu = next) {
		next = (dmu_buf_user_t *)list_next(evict_list_p, dbu);
		list_remove(evict_list_p, dbu);
		dbu->evict_func(dbu);
	}
}
static inline void
dmu_buf_destroy_user_evict_list(list_t *evict_list_p)
{
	dmu_buf_process_user_evicts(evict_list_p);
	list_destroy(evict_list_p);
}

/*
 * The names of zap entries in the DIRECTORY_OBJECT of the MOS.
 */
#define	DMU_POOL_DIRECTORY_OBJECT	1
#define	DMU_POOL_CONFIG			"config"
#define	DMU_POOL_FEATURES_FOR_WRITE	"features_for_write"
#define	DMU_POOL_FEATURES_FOR_READ	"features_for_read"
#define	DMU_POOL_FEATURE_DESCRIPTIONS	"feature_descriptions"
#define	DMU_POOL_ROOT_DATASET		"root_dataset"
#define	DMU_POOL_SYNC_BPOBJ		"sync_bplist"
#define	DMU_POOL_ERRLOG_SCRUB		"errlog_scrub"
#define	DMU_POOL_ERRLOG_LAST		"errlog_last"
#define	DMU_POOL_SPARES			"spares"
#define	DMU_POOL_DEFLATE		"deflate"
#define	DMU_POOL_HISTORY		"history"
#define	DMU_POOL_PROPS			"pool_props"
#define	DMU_POOL_L2CACHE		"l2cache"
#define	DMU_POOL_TMP_USERREFS		"tmp_userrefs"
#define	DMU_POOL_DDT			"DDT-%s-%s-%s"
#define	DMU_POOL_DDT_STATS		"DDT-statistics"
#define	DMU_POOL_CREATION_VERSION	"creation_version"
#define	DMU_POOL_SCAN			"scan"
#define	DMU_POOL_FREE_BPOBJ		"free_bpobj"
#define	DMU_POOL_BPTREE_OBJ		"bptree_obj"
#define	DMU_POOL_EMPTY_BPOBJ		"empty_bpobj"

uint64_t dmu_object_alloc(objset_t *os, dmu_object_type_t ot,
    int blocksize, dmu_object_type_t bonus_type, int bonus_len, dmu_tx_t *tx);
int dmu_object_claim(objset_t *os, uint64_t object, dmu_object_type_t ot,
    int blocksize, dmu_object_type_t bonus_type, int bonus_len, dmu_tx_t *tx);
int dmu_object_reclaim(objset_t *os, uint64_t object, dmu_object_type_t ot,
    int blocksize, dmu_object_type_t bonustype, int bonuslen);

int dmu_object_free(objset_t *os, uint64_t object, dmu_tx_t *tx);

int dmu_object_next(objset_t *os, uint64_t *objectp,
    boolean_t hole, uint64_t txg);

int dmu_object_set_blocksize(objset_t *os, uint64_t object, uint64_t size,
    int ibs, dmu_tx_t *tx);

void dmu_object_set_checksum(objset_t *os, uint64_t object, uint8_t checksum,
    dmu_tx_t *tx);

void dmu_object_set_compress(objset_t *os, uint64_t object, uint8_t compress,
    dmu_tx_t *tx);

#define	WP_NOFILL	0x1
#define	WP_DMU_SYNC	0x2
#define	WP_SPILL	0x4

void dmu_write_policy(objset_t *os, struct dnode *dn, int level, int wp,
    struct zio_prop *zp);
int dmu_bonus_hold(objset_t *os, uint64_t object, void *tag, dmu_buf_t **);
int dmu_bonus_max(void);
int dmu_set_bonus(dmu_buf_t *, int, dmu_tx_t *);
int dmu_set_bonustype(dmu_buf_t *, dmu_object_type_t, dmu_tx_t *);
dmu_object_type_t dmu_get_bonustype(dmu_buf_t *);
int dmu_rm_spill(objset_t *, uint64_t, dmu_tx_t *);

/*
 * Special spill buffer support used by "SA" framework
 */

int dmu_spill_hold_by_bonus(dmu_buf_t *bonus, void *tag, dmu_buf_t **dbp);
int dmu_spill_hold_by_dnode(struct dnode *dn, uint32_t flags,
    void *tag, dmu_buf_t **dbp);
int dmu_spill_hold_existing(dmu_buf_t *bonus, void *tag, dmu_buf_t **dbp);

int dmu_buf_hold(objset_t *os, uint64_t object, uint64_t offset,
    void *tag, dmu_buf_t **, int flags);
void dmu_buf_add_ref(dmu_buf_t *db, void* tag);
void dmu_buf_rele(dmu_buf_t *db, void *tag);
uint64_t dmu_buf_refcount(dmu_buf_t *db);

int dmu_buf_hold_array_by_bonus(dmu_buf_t *db, uint64_t offset,
    uint64_t length, int read, void *tag, int *numbufsp, dmu_buf_t ***dbpp);
void dmu_buf_rele_array(dmu_buf_t **, int numbufs, void *tag);

dmu_buf_user_t *dmu_buf_set_user(dmu_buf_t *db, dmu_buf_user_t *user);
dmu_buf_user_t *dmu_buf_set_user_ie(dmu_buf_t *db, dmu_buf_user_t *user);
dmu_buf_user_t *dmu_buf_replace_user(dmu_buf_t *db,
    dmu_buf_user_t *old_user, dmu_buf_user_t *new_user);
dmu_buf_user_t *dmu_buf_remove_user(dmu_buf_t *db, dmu_buf_user_t *user);
void dmu_evict_user(objset_t *os, dmu_buf_evict_func_t *func);

dmu_buf_user_t *dmu_buf_get_user(dmu_buf_t *db);

void dmu_buf_will_dirty(dmu_buf_t *db, dmu_tx_t *tx);
void dmu_buf_will_dirty_range(dmu_buf_t *db, dmu_tx_t *tx, int offset,
    int size);

boolean_t dmu_buf_freeable(dmu_buf_t *);

#define	DMU_NEW_OBJECT	(-1ULL)
#define	DMU_OBJECT_END	(-1ULL)

dmu_tx_t *dmu_tx_create(objset_t *os);
void dmu_tx_hold_write(dmu_tx_t *tx, uint64_t object, uint64_t off, int len);
void dmu_tx_hold_free(dmu_tx_t *tx, uint64_t object, uint64_t off,
    uint64_t len);
void dmu_tx_hold_zap(dmu_tx_t *tx, uint64_t object, int add, const char *name);
void dmu_tx_hold_bonus(dmu_tx_t *tx, uint64_t object);
void dmu_tx_hold_spill(dmu_tx_t *tx, uint64_t object);
void dmu_tx_hold_sa(dmu_tx_t *tx, struct sa_handle *hdl, boolean_t may_grow);
void dmu_tx_hold_sa_create(dmu_tx_t *tx, int total_size);
void dmu_tx_abort(dmu_tx_t *tx);
int dmu_tx_assign(dmu_tx_t *tx, uint64_t txg_how);
void dmu_tx_wait(dmu_tx_t *tx);
void dmu_tx_commit(dmu_tx_t *tx);

typedef void dmu_tx_callback_func_t(void *dcb_data, int error);

void dmu_tx_callback_register(dmu_tx_t *tx, dmu_tx_callback_func_t *dcb_func,
    void *dcb_data);

/*
 * Free up the data blocks for a defined range of a file.  If size is
 * -1, the range from offset to end-of-file is freed.
 */
int dmu_free_range(objset_t *os, uint64_t object, uint64_t offset,
	uint64_t size, dmu_tx_t *tx);
int dmu_free_long_range(objset_t *os, uint64_t object, uint64_t offset,
	uint64_t size);
int dmu_free_object(objset_t *os, uint64_t object);

void dmu_buf_cb_process(void);

/*
 * Convenience functions.
 *
 * Canfail routines will return 0 on success, or an errno if there is a
 * nonrecoverable I/O error.
 */
// XXX REMOVE THESE IN FAVOR OF DMU_CTX_FLAG_PREFETCH
#define	DMU_READ_PREFETCH	0 /* prefetch */
#define	DMU_READ_NO_PREFETCH	1 /* don't prefetch */

int dmu_read(objset_t *os, uint64_t object, uint64_t offset, uint64_t size,
	void *buf, uint32_t flags);
int dmu_issue(dmu_context_t *dmu_ctx);
void dmu_write(objset_t *os, uint64_t object, uint64_t offset, uint64_t size,
	const void *buf, dmu_tx_t *tx);
int dmu_prealloc(objset_t *os, uint64_t object, uint64_t offset, uint64_t size,
	dmu_tx_t *tx);
int dmu_read_uio(objset_t *os, uint64_t object, struct uio *uio, uint64_t size);
int dmu_write_uio(objset_t *os, uint64_t object, struct uio *uio, uint64_t size,
    dmu_tx_t *tx);
int dmu_write_uio_dbuf(dmu_buf_t *zdb, struct uio *uio, uint64_t size,
    dmu_tx_t *tx);
int dmu_write_pages(objset_t *os, uint64_t object, uint64_t offset,
    uint64_t size, struct page *pp, dmu_tx_t *tx);
struct arc_buf *dmu_request_arcbuf(dmu_buf_t *handle, int size);
void dmu_return_arcbuf(struct arc_buf *buf);
void dmu_assign_arcbuf(dmu_buf_t *handle, uint64_t offset, struct arc_buf *buf,
    dmu_tx_t *tx);
int dmu_xuio_init(struct xuio *uio, int niov);
void dmu_xuio_fini(struct xuio *uio);
int dmu_xuio_add(struct xuio *uio, struct arc_buf *abuf, offset_t off,
    size_t n);
int dmu_xuio_cnt(struct xuio *uio);
struct arc_buf *dmu_xuio_arcbuf(struct xuio *uio, int i);
void dmu_xuio_clear(struct xuio *uio, int i);
void xuio_stat_wbuf_copied();
void xuio_stat_wbuf_nocopy();

extern int zfs_prefetch_disable;

void dmu_prefetch(objset_t *os, uint64_t object, uint64_t offset,
    uint64_t len);

/** All sizes are in bytes unless otherwise indicated. */
typedef struct dmu_object_info {
	uint32_t doi_data_block_size;
	uint32_t doi_metadata_block_size;
	dmu_object_type_t doi_type;
	dmu_object_type_t doi_bonus_type;
	uint64_t doi_bonus_size;
	uint8_t doi_indirection;		/**< 2 = dnode->indirect->data*/
	uint8_t doi_checksum;
	uint8_t doi_compress;
	uint8_t doi_pad[5];
	uint64_t doi_physical_blocks_512;	/**<data + metadata, 512b blks*/
	uint64_t doi_max_offset;
	uint64_t doi_fill_count;		/**<number of non-empty blocks*/
} dmu_object_info_t;

typedef void arc_byteswap_func_t(void *buf, size_t size);

typedef struct dmu_object_type_info {
	dmu_object_byteswap_t	ot_byteswap;
	boolean_t		ot_metadata;
	char			*ot_name;
} dmu_object_type_info_t;

typedef struct dmu_object_byteswap_info {
	arc_byteswap_func_t	*ob_func;
	char			*ob_name;
} dmu_object_byteswap_info_t;

extern const dmu_object_type_info_t dmu_ot[DMU_OT_NUMTYPES];
extern const dmu_object_byteswap_info_t dmu_ot_byteswap[DMU_BSWAP_NUMFUNCS];

int dmu_object_info(objset_t *os, uint64_t object, dmu_object_info_t *doi);
void dmu_object_info_from_dnode(struct dnode *dn, dmu_object_info_t *doi);
void dmu_object_info_from_db(dmu_buf_t *db, dmu_object_info_t *doi);
void dmu_object_size_from_db(dmu_buf_t *db, uint32_t *blksize,
    u_longlong_t *nblk512);

typedef struct dmu_objset_stats {
	uint64_t dds_num_clones; /**< number of clones of this */
	uint64_t dds_creation_txg;
	uint64_t dds_guid;
	dmu_objset_type_t dds_type;
	uint8_t dds_is_snapshot;
	uint8_t dds_inconsistent;
	char dds_origin[MAXNAMELEN];
} dmu_objset_stats_t;

void dmu_objset_fast_stat(objset_t *os, dmu_objset_stats_t *stat);

void dmu_objset_stats(objset_t *os, struct nvlist *nv);

void dmu_objset_space(objset_t *os, uint64_t *refdbytesp, uint64_t *availbytesp,
    uint64_t *usedobjsp, uint64_t *availobjsp);

uint64_t dmu_objset_fsid_guid(objset_t *os);

timestruc_t dmu_objset_snap_cmtime(objset_t *os);

int dmu_objset_is_snapshot(objset_t *os);

extern struct spa *dmu_objset_spa(objset_t *os);
extern struct zilog *dmu_objset_zil(objset_t *os);
extern struct dsl_pool *dmu_objset_pool(objset_t *os);
extern struct dsl_dataset *dmu_objset_ds(objset_t *os);
extern void dmu_objset_name(objset_t *os, char *buf);
extern dmu_objset_type_t dmu_objset_type(objset_t *os);
extern uint64_t dmu_objset_id(objset_t *os);
extern uint64_t dmu_objset_syncprop(objset_t *os);
extern uint64_t dmu_objset_logbias(objset_t *os);
extern int dmu_snapshot_list_next(objset_t *os, int namelen, char *name,
    uint64_t *id, uint64_t *offp, boolean_t *case_conflict);
extern int dmu_snapshot_realname(objset_t *os, char *name, char *real,
    int maxlen, boolean_t *conflict);
extern int dmu_dir_list_next(objset_t *os, int namelen, char *name,
    uint64_t *idp, uint64_t *offp);

typedef int objset_used_cb_t(dmu_object_type_t bonustype,
    void *bonus, uint64_t *userp, uint64_t *groupp);
extern void dmu_objset_register_type(dmu_objset_type_t ost,
    objset_used_cb_t *cb);
extern void dmu_objset_set_user(objset_t *os, void *user_ptr);
extern void *dmu_objset_get_user(objset_t *os);

uint64_t dmu_tx_get_txg(dmu_tx_t *tx);

/**
 * {zfs,zvol,ztest}_get_done() args
 */
typedef struct zgd {
	struct zilog	*zgd_zilog;
	struct blkptr	*zgd_bp;
	dmu_buf_t	*zgd_db;
	struct rl	*zgd_rl;
	void		*zgd_private;
} zgd_t;

typedef void dmu_sync_cb_t(zgd_t *arg, int error);
int dmu_sync(struct zio *zio, uint64_t txg, dmu_sync_cb_t *done, zgd_t *zgd);

int dmu_offset_next(objset_t *os, uint64_t object, boolean_t hole,
    uint64_t *off);

extern void dmu_init(void);
extern void dmu_fini(void);

typedef void (*dmu_traverse_cb_t)(objset_t *os, void *arg, struct blkptr *bp,
    uint64_t object, uint64_t offset, int len);
void dmu_traverse_objset(objset_t *os, uint64_t txg_start,
    dmu_traverse_cb_t cb, void *arg);

int dmu_send(objset_t *tosnap, objset_t *fromsnap, boolean_t fromorigin,
    int outfd, struct file *fp, offset_t *off);
int dmu_send_estimate(objset_t *tosnap, objset_t *fromsnap,
    boolean_t fromorigin, uint64_t *sizep);

/**
 * This structure is opaque!
 *
 * If logical and real are different, we are recving the stream
 * into the "real" temporary clone, and then switching it with
 * the "logical" target.
 */
typedef struct dmu_recv_cookie {
	struct dsl_dataset *drc_logical_ds;
	struct dsl_dataset *drc_real_ds;
	struct drr_begin *drc_drrb;
	char *drc_tosnap;
	char *drc_top_ds;
	boolean_t drc_newfs;
	boolean_t drc_force;
	struct avl_tree *drc_guid_to_ds_map;
} dmu_recv_cookie_t;

int dmu_recv_begin(char *tofs, char *tosnap, char *topds, struct drr_begin *,
    boolean_t force, objset_t *origin, dmu_recv_cookie_t *);
int dmu_recv_stream(dmu_recv_cookie_t *drc, struct file *fp, offset_t *voffp,
    int cleanup_fd, uint64_t *action_handlep);
int dmu_recv_end(dmu_recv_cookie_t *drc);

int dmu_diff(objset_t *tosnap, objset_t *fromsnap, struct file *fp,
    offset_t *off);

#define	ZFS_CRC64_POLY	0xC96C5795D7870F42ULL	/**< ECMA-182, reflected form */
/* CRC64 table */
extern uint64_t zfs_crc64_table[256];

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DMU_H */
