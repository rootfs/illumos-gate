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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 * Copyright (c) 2013 by Saso Kiselkov. All rights reserved.
 */

#include <sys/zfs_context.h>
#include <sys/dmu.h>
#include <sys/dmu_impl.h>
#include <sys/dbuf.h>
#include <sys/dmu_objset.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dmu_tx.h>
#include <sys/spa.h>
#include <sys/zio.h>
#include <sys/dmu_zfetch.h>
#include <sys/sa.h>
#include <sys/sa_impl.h>
#include <machine/_inttypes.h>

static void dbuf_destroy(dmu_buf_impl_t *db);
static boolean_t dbuf_undirty(dmu_buf_impl_t *db, dmu_tx_t *tx);
static zio_t *dbuf_write(dbuf_dirty_record_t *dr, arc_buf_t *data,
    dmu_tx_t *tx);
static arc_evict_func_t dbuf_do_evict;

#define	IN_RANGE(x, val, y) ((val) >= (x) && (val) <= (y))
#define	_DBUF_CONSTANT_FMT \
	" offset %llu os %p level %d holds %lld dirty %d state %d\n"
#define	_DBUF_CONSTANT_FMT_ARGS(db) \
	(db)->db.db_offset, (db)->db_objset, (db)->db_level, \
	refcount_count(&(db)->db_holds), (db)->db_dirtycnt, (db)->db_state

#define	tmpprintf(args...) do { } while (0)

/*
 * Global data structures and functions for the dbuf cache.
 */
static kmem_cache_t *dbuf_cache;

/* ARGSUSED */
static int
dbuf_cons(void *vdb, void *unused, int kmflag)
{
	dmu_buf_impl_t *db = vdb;
	bzero(db, sizeof (dmu_buf_impl_t));

	mutex_init(&db->db_mtx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&db->db_changed, NULL, CV_DEFAULT, NULL);
	refcount_create(&db->db_holds);
	return (0);
}

/* ARGSUSED */
static void
dbuf_dest(void *vdb, void *unused)
{
	dmu_buf_impl_t *db = vdb;
	mutex_destroy(&db->db_mtx);
	cv_destroy(&db->db_changed);
	refcount_destroy(&db->db_holds);
}

/*
 * dbuf hash table routines
 */
static dbuf_hash_table_t dbuf_hash_table;

SYSCTL_DECL(_vfs_zfs);
SYSCTL_NODE(_vfs_zfs, OID_AUTO, dbuf, CTLFLAG_RW, 0, "ZFS DBUF");
#ifdef ZFS_DEBUG
DEBUG_REFCOUNT(_vfs_zfs_dbuf, dirty_ranges_in_flight,
    "number of dirty ranges in flight");
DEBUG_COUNTER_U(_vfs_zfs_dbuf, dirty_ranges_total,
    "number of total dirty ranges");
DEBUG_COUNTER_U(_vfs_zfs_dbuf, user_evicts, "number of user evicts performed");
DEBUG_COUNTER_U(_vfs_zfs_dbuf, resolves_completed,
    "number of resolves completed");
/* The next two must be equal to avoid deadlocks */
DEBUG_COUNTER_U(_vfs_zfs_dbuf, syncer_deferred_resolves,
    "number of syncer deferred resolves");
DEBUG_COUNTER_U(_vfs_zfs_dbuf, syncer_deferred_write_zios,
    "number of syncer deferred write zios executed");
/* The next two must be equal to avoid deadlocks */
DEBUG_COUNTER_U(_vfs_zfs_dbuf, override_deferred_resolves,
    "number of override deferred resolves");
DEBUG_COUNTER_U(_vfs_zfs_dbuf, override_deferred_write_zios,
    "number of override deferred write zios executed");
#endif
DEBUG_COUNTER_U(_vfs_zfs_dbuf, dirty_writes_lost, "dirty writes lost");

static uint64_t dbuf_hash_count;

static uint64_t
dbuf_hash(void *os, uint64_t obj, uint8_t lvl, uint64_t blkid)
{
	uintptr_t osv = (uintptr_t)os;
	uint64_t crc = -1ULL;

	ASSERT(zfs_crc64_table[128] == ZFS_CRC64_POLY);
	crc = (crc >> 8) ^ zfs_crc64_table[(crc ^ (lvl)) & 0xFF];
	crc = (crc >> 8) ^ zfs_crc64_table[(crc ^ (osv >> 6)) & 0xFF];
	crc = (crc >> 8) ^ zfs_crc64_table[(crc ^ (obj >> 0)) & 0xFF];
	crc = (crc >> 8) ^ zfs_crc64_table[(crc ^ (obj >> 8)) & 0xFF];
	crc = (crc >> 8) ^ zfs_crc64_table[(crc ^ (blkid >> 0)) & 0xFF];
	crc = (crc >> 8) ^ zfs_crc64_table[(crc ^ (blkid >> 8)) & 0xFF];

	crc ^= (osv>>14) ^ (obj>>16) ^ (blkid>>16);

	return (crc);
}

#define	DBUF_STATE_CHANGE(db, op, state, why) do {			\
	(db)->db_state op state;					\
	DTRACE_PROBE2(dbuf__state_change, dmu_buf_impl_t *, db,		\
	    const char *, why);						\
} while(0)

#define	DBUF_HASH(os, obj, level, blkid) dbuf_hash(os, obj, level, blkid);

#define	DBUF_EQUAL(dbuf, os, obj, level, blkid)		\
	((dbuf)->db.db_object == (obj) &&		\
	(dbuf)->db_objset == (os) &&			\
	(dbuf)->db_level == (level) &&			\
	(dbuf)->db_blkid == (blkid))

dmu_buf_impl_t *
dbuf_find(dnode_t *dn, uint8_t level, uint64_t blkid)
{
	dbuf_hash_table_t *h = &dbuf_hash_table;
	objset_t *os = dn->dn_objset;
	uint64_t obj = dn->dn_object;
	uint64_t hv = DBUF_HASH(os, obj, level, blkid);
	uint64_t idx = hv & h->hash_table_mask;
	dmu_buf_impl_t *db;

	mutex_enter(DBUF_HASH_MUTEX(h, idx));
	for (db = h->hash_table[idx]; db != NULL; db = db->db_hash_next) {
		if (DBUF_EQUAL(db, os, obj, level, blkid)) {
			mutex_enter(&db->db_mtx);
			if (db->db_state != DB_EVICTING) {
				mutex_exit(DBUF_HASH_MUTEX(h, idx));
				return (db);
			}
			mutex_exit(&db->db_mtx);
		}
	}
	mutex_exit(DBUF_HASH_MUTEX(h, idx));
	return (NULL);
}

/*
 * Insert an entry into the hash table.  If there is already an element
 * equal to elem in the hash table, then the already existing element
 * will be returned and the new element will not be inserted.
 * Otherwise returns NULL.
 */
static dmu_buf_impl_t *
dbuf_hash_insert(dmu_buf_impl_t *db)
{
	dbuf_hash_table_t *h = &dbuf_hash_table;
	objset_t *os = db->db_objset;
	uint64_t obj = db->db.db_object;
	int level = db->db_level;
	uint64_t blkid = db->db_blkid;
	uint64_t hv = DBUF_HASH(os, obj, level, blkid);
	uint64_t idx = hv & h->hash_table_mask;
	dmu_buf_impl_t *dbf;

	mutex_enter(DBUF_HASH_MUTEX(h, idx));
	for (dbf = h->hash_table[idx]; dbf != NULL; dbf = dbf->db_hash_next) {
		if (DBUF_EQUAL(dbf, os, obj, level, blkid)) {
			mutex_enter(&dbf->db_mtx);
			if (dbf->db_state != DB_EVICTING) {
				mutex_exit(DBUF_HASH_MUTEX(h, idx));
				return (dbf);
			}
			mutex_exit(&dbf->db_mtx);
		}
	}

	mutex_enter(&db->db_mtx);
	db->db_hash_next = h->hash_table[idx];
	h->hash_table[idx] = db;
	mutex_exit(DBUF_HASH_MUTEX(h, idx));
	atomic_add_64(&dbuf_hash_count, 1);

	return (NULL);
}

/*
 * Remove an entry from the hash table.  This operation will
 * fail if there are any existing holds on the db.
 */
static void
dbuf_hash_remove(dmu_buf_impl_t *db)
{
	dbuf_hash_table_t *h = &dbuf_hash_table;
	uint64_t hv = DBUF_HASH(db->db_objset, db->db.db_object,
	    db->db_level, db->db_blkid);
	uint64_t idx = hv & h->hash_table_mask;
	dmu_buf_impl_t *dbf, **dbp;

	/*
	 * We musn't hold db_mtx to maintin lock ordering:
	 * DBUF_HASH_MUTEX > db_mtx.
	 */
	ASSERT(refcount_is_zero(&db->db_holds));
	ASSERT(db->db_state == DB_EVICTING);
	ASSERT(!MUTEX_HELD(&db->db_mtx));

	mutex_enter(DBUF_HASH_MUTEX(h, idx));
	dbp = &h->hash_table[idx];
	while ((dbf = *dbp) != db) {
		dbp = &dbf->db_hash_next;
		ASSERT(dbf != NULL);
	}
	*dbp = db->db_hash_next;
	db->db_hash_next = NULL;
	mutex_exit(DBUF_HASH_MUTEX(h, idx));
	atomic_add_64(&dbuf_hash_count, -1);
}

static void
dbuf_verify_user(dmu_buf_impl_t *db, boolean_t evicting)
{
#ifdef ZFS_DEBUG

	if (db->db_level != 0)
		ASSERT(db->db_user == NULL);

	if (db->db_user == NULL)
		return;

	/* Clients must resolve a dbuf before attaching user data. */
	ASSERT(db->db.db_data != NULL && db->db_state == DB_CACHED);

	/*
	 * NB: We cannot assert anything about the relationship between
	 * holds and dirties if we are evicting, because holds can be
	 * modified at any time.  But we can assert that there are holds if
	 * we aren't evicting.
	 */
	if (!evicting) {
		int64_t holds = refcount_count(&db->db_holds);

		if (db->db_immediate_evict == TRUE)
			ASSERT(holds > db->db_dirtycnt);
		else
			ASSERT(holds > 0);
	}
#endif
}

/*
 * Evict the dbuf's user, either immediately, or use a provided queue.
 *
 * Call dmu_buf_process_user_evicts or dmu_buf_destroy_user_evict_list
 * on the list when finished generating it.
 *
 * NOTE: If db->db_immediate_evict is FALSE, evict_list_p must be provided.
 * NOTE: See dmu_buf_user_t about how this process works.
 */
static void
dbuf_evict_user(dmu_buf_impl_t *db, list_t *evict_list_p)
{
	ASSERT(MUTEX_HELD(&db->db_mtx));
	ASSERT(evict_list_p != NULL);
	dbuf_verify_user(db, /*evicting*/B_TRUE);

	if (db->db_user == NULL)
		return;

	DEBUG_COUNTER_INC(user_evicts);
	ASSERT(!list_link_active(&db->db_user->dbu_evict_queue_link));
	list_insert_head(evict_list_p, db->db_user);
	db->db_user = NULL;
}

/*
 * Replace the current user of the dbuf.  Requires that the caller knows who
 * the old user is.  Returns the old user, which may not necessarily be
 * the same old_user provided by the caller.
 */
void *
dmu_buf_replace_user(dmu_buf_t *db_fake, dmu_buf_user_t *old_user,
    dmu_buf_user_t *new_user)
{
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)db_fake;

	mutex_enter(&db->db_mtx);
	dbuf_verify_user(db, /*evicting*/B_FALSE);
	if (db->db_user == old_user)
		db->db_user = new_user;
	else
		old_user = db->db_user;
	dbuf_verify_user(db, /*evicting*/B_FALSE);
	mutex_exit(&db->db_mtx);

	return (old_user);
}

/*
 * Set the user eviction data for the DMU buffer.  Returns NULL on success,
 * or the existing user if another user currently owns the buffer.
 */
void *
dmu_buf_set_user(dmu_buf_t *db_fake, dmu_buf_user_t *user)
{
	return (dmu_buf_replace_user(db_fake, NULL, user));
}

/*
 * Remove the user eviction data for the DMU buffer.  Returns the provided
 * user on success; otherwise returns NULL if no user owned the buffer, or
 * some other user.
 */
void *
dmu_buf_remove_user(dmu_buf_t *db_fake, dmu_buf_user_t *user)
{
	return (dmu_buf_replace_user(db_fake, user, NULL));
}

void *
dmu_buf_set_user_ie(dmu_buf_t *db_fake, dmu_buf_user_t *user)
{
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)db_fake;

	db->db_immediate_evict = TRUE;
	return (dmu_buf_set_user(db_fake, user));
}

/*
 * Returns the db_user set with dmu_buf_update_user(), or NULL if not set.
 */
void *
dmu_buf_get_user(dmu_buf_t *db_fake)
{
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)db_fake;

	dbuf_verify_user(db, /*evicting*/B_FALSE);
	return (db->db_user);
}

/*
 * Clear the dbuf's ARC buffer.
 */
static void
dbuf_clear_data(dmu_buf_impl_t *db, list_t *evict_list_p)
{
	ASSERT(MUTEX_HELD(&db->db_mtx));
	ASSERT(db->db_buf == NULL || !arc_has_callback(db->db_buf));
	dbuf_evict_user(db, evict_list_p);
	db->db_buf = NULL;
	db->db.db_data = NULL;
	if (db->db_state != DB_NOFILL)
		DBUF_STATE_CHANGE(db, =, DB_UNCACHED, "clear data");
}

/*
 * Set the dbuf's buffer to the ARC buffer, including any associated state,
 * such as db_data.
 */
static void
dbuf_set_data(dmu_buf_impl_t *db, arc_buf_t *buf)
{
	ASSERT(MUTEX_HELD(&db->db_mtx));
	ASSERT(db->db_buf == NULL || !arc_has_callback(db->db_buf));
	ASSERT(buf != NULL);

	db->db_buf = buf;
	db->db_buf->b_last_dbuf = db;
	ASSERT(buf->b_data != NULL);
	db->db.db_data = buf->b_data;
	if (!arc_released(buf))
		arc_set_callback(buf, dbuf_do_evict, db);
}

boolean_t
dbuf_is_metadata(dmu_buf_impl_t *db)
{
	if (db->db_level > 0) {
		return (B_TRUE);
	} else {
		boolean_t is_metadata;

		DB_DNODE_ENTER(db);
		is_metadata = DMU_OT_IS_METADATA(DB_DNODE(db)->dn_type);
		DB_DNODE_EXIT(db);

		return (is_metadata);
	}
}

void
dbuf_evict(dmu_buf_impl_t *db, list_t *evict_list_p)
{
	ASSERT(MUTEX_HELD(&db->db_mtx));
	ASSERT(db->db_buf == NULL);
	ASSERT(db->db_data_pending == NULL);

	dbuf_clear(db, evict_list_p);
	dbuf_destroy(db);
}

void
dbuf_init(void)
{
	uint64_t hsize = 1ULL << 16;
	dbuf_hash_table_t *h = &dbuf_hash_table;
	int i;

	/*
	 * The hash table is big enough to fill all of physical memory
	 * with an average 4K block size.  The table will take up
	 * totalmem*sizeof(void*)/4K (i.e. 2MB/GB with 8-byte pointers).
	 */
	while (hsize * 4096 < (uint64_t)physmem * PAGESIZE)
		hsize <<= 1;

retry:
	h->hash_table_mask = hsize - 1;
	h->hash_table = kmem_zalloc(hsize * sizeof (void *), KM_NOSLEEP);
	if (h->hash_table == NULL) {
		/* XXX - we should really return an error instead of assert */
		ASSERT(hsize > (1ULL << 10));
		hsize >>= 1;
		goto retry;
	}

	dbuf_cache = kmem_cache_create("dmu_buf_impl_t",
	    sizeof (dmu_buf_impl_t),
	    0, dbuf_cons, dbuf_dest, NULL, NULL, NULL, 0);

	for (i = 0; i < DBUF_MUTEXES; i++)
		mutex_init(&h->hash_mutexes[i], NULL, MUTEX_DEFAULT, NULL);
}

void
dbuf_fini(void)
{
	dbuf_hash_table_t *h = &dbuf_hash_table;
	int i;

	for (i = 0; i < DBUF_MUTEXES; i++)
		mutex_destroy(&h->hash_mutexes[i]);
	kmem_free(h->hash_table, (h->hash_table_mask + 1) * sizeof (void *));
	kmem_cache_destroy(dbuf_cache);
}

/*
 * Other stuff.
 */

#ifdef ZFS_DEBUG
static void
dbuf_verify(dmu_buf_impl_t *db)
{
	dnode_t *dn;
	dbuf_dirty_record_t *dr;
	dbuf_dirty_record_t *dr_next;
	dbuf_dirty_record_t *pending;

	ASSERT(MUTEX_HELD(&db->db_mtx));

	if (!(zfs_flags & ZFS_DEBUG_DBUF_VERIFY))
		return;

	ASSERT(db->db_objset != NULL);
	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);
	if (dn == NULL) {
		ASSERT(db->db_parent == NULL);
		ASSERT(db->db_blkptr == NULL);
	} else {
		ASSERT3U(db->db.db_object, ==, dn->dn_object);
		ASSERT3P(db->db_objset, ==, dn->dn_objset);
		ASSERT3U(db->db_level, <, dn->dn_nlevels);
		ASSERT(db->db_blkid == DMU_BONUS_BLKID ||
		    db->db_blkid == DMU_SPILL_BLKID ||
		    !list_is_empty(&dn->dn_dbufs));
	}
	if (db->db_blkid == DMU_BONUS_BLKID) {
		ASSERT(dn != NULL);
		ASSERT3U(db->db.db_size, >=, dn->dn_bonuslen);
		ASSERT3U(db->db.db_offset, ==, DMU_BONUS_BLKID);
	} else if (db->db_blkid == DMU_SPILL_BLKID) {
		ASSERT(dn != NULL);
		ASSERT3U(db->db.db_size, >=, dn->dn_bonuslen);
		ASSERT0(db->db.db_offset);
	} else {
		ASSERT3U(db->db.db_offset, ==, db->db_blkid * db->db.db_size);
	}

	pending = NULL;
	for (dr = list_head(&db->db_dirty_records); dr != NULL; dr = dr_next) {
		dr_next = list_next(&db->db_dirty_records, dr);
		ASSERT(dr->dr_dbuf == db);
		ASSERT(dr_next == NULL || dr->dr_txg > dr_next->dr_txg);
		/* This DR happens to be the pending DR. */
		if (dr == db->db_data_pending) {
			pending = dr;
			ASSERT(dr_next == NULL);
		}
	}
	if (db->db_data_pending != NULL) {
		/* The pending DR's dbuf is this dbuf. */
		ASSERT(db->db_data_pending->dr_dbuf == db);
		/* The pending DR should be on the list. */
		ASSERT(pending == db->db_data_pending);
	}

	/*
	 * We can't assert that db_size matches dn_datablksz because it
	 * can be momentarily different when another thread is doing
	 * dnode_set_blksz().
	 */
	if (db->db_level == 0 && db->db.db_object == DMU_META_DNODE_OBJECT) {
		dr = db->db_data_pending;
		/*
		 * It should only be modified in syncing context, so
		 * make sure we only have one copy of the data.
		 */
		ASSERT(dr == NULL || dr->dt.dl.dr_data == db->db_buf);
	}

	/* verify db->db_blkptr */
	if (db->db_blkptr) {
		if (db->db_parent == dn->dn_dbuf) {
			/* db is pointed to by the dnode */
			/* ASSERT3U(db->db_blkid, <, dn->dn_nblkptr); */
			if (DMU_OBJECT_IS_SPECIAL(db->db.db_object))
				ASSERT(db->db_parent == NULL);
			else
				ASSERT(db->db_parent != NULL);
			if (db->db_blkid != DMU_SPILL_BLKID)
				ASSERT3P(db->db_blkptr, ==,
				    &dn->dn_phys->dn_blkptr[db->db_blkid]);
		} else {
			/* db is pointed to by an indirect block */
			int epb = db->db_parent->db.db_size >> SPA_BLKPTRSHIFT;
			ASSERT3U(db->db_parent->db_level, ==, db->db_level+1);
			ASSERT3U(db->db_parent->db.db_object, ==,
			    db->db.db_object);
			/*
			 * dnode_grow_indblksz() can make this fail if we don't
			 * have the struct_rwlock.  XXX indblksz no longer
			 * grows.  safe to do this now?
			 */
			if (RW_WRITE_HELD(&dn->dn_struct_rwlock)) {
				ASSERT3P(db->db_blkptr, ==,
				    ((blkptr_t *)db->db_parent->db.db_data +
				    db->db_blkid % epb));
			}
		}
	}
	/*
	 * XXX
	 * We may need to modify the state check here if something may be
	 * in DB_FILL and have dirty parts, depending on how db_state
	 * semantics are changed.
	 *
	 * XXX
	 * Why does this ignore DB_FILL in the first place?  DB_FILL
	 * still dirties the buffer and must be sunk too.
	 */
	if ((db->db_blkptr == NULL || BP_IS_HOLE(db->db_blkptr)) &&
	    (db->db_buf == NULL || db->db_buf->b_data) &&
	    db->db.db_data && db->db_blkid != DMU_BONUS_BLKID &&
	    db->db_state != DB_FILL && !dn->dn_free_txg) {
		/*
		 * If the blkptr isn't set but they have nonzero data,
		 * it had better be dirty, otherwise we'll lose that
		 * data when we evict this buffer.
		 */
		if (db->db_dirtycnt == 0) {
			uint64_t *buf = db->db.db_data;
			int i;

			for (i = 0; i < db->db.db_size >> 3; i++) {
				ASSERT(buf[i] == 0);
			}
		}
	}

	/* Some dbufs can't have buffer sets. */
	ASSERT(db->db_blkid != DMU_BONUS_BLKID ||
	    list_is_empty(&db->db_dmu_buf_sets));

	/* Dbuf state checks. */
	/* If a dbuf is partial, it can only have one dirty record. */
	ASSERT((db->db_state & DB_PARTIAL) == 0 || db->db_dirtycnt == 1);

	/*
	 * Returns 1 if either the bitmask is not set or those are the only
	 * bits set, with exceptions where they are acceptable.
	 */
#define BITMASK_SET(val, bitmask, exceptions)				\
	(((val) & (bitmask)) == 0 || ((val) & (~(bitmask|exceptions))) == 0)
#define BITMASK_SET_EXCLUSIVE(val, bitmask) BITMASK_SET(val, bitmask, 0)

	ASSERT(BITMASK_SET_EXCLUSIVE(db->db_state, DB_UNCACHED));
	ASSERT(BITMASK_SET_EXCLUSIVE(db->db_state, DB_NOFILL));
	ASSERT(BITMASK_SET_EXCLUSIVE(db->db_state, DB_CACHED));
	ASSERT(BITMASK_SET_EXCLUSIVE(db->db_state, DB_EVICTING));
	ASSERT(BITMASK_SET(db->db_state, DB_PARTIAL, DB_FILL));
	ASSERT(BITMASK_SET(db->db_state, DB_READ, DB_FILL));
	ASSERT(BITMASK_SET(db->db_state, DB_FILL, (DB_PARTIAL|DB_READ)));
#undef BITMASK_SET_EXCLUSIVE
#undef BITMASK_SET

	DB_DNODE_EXIT(db);
}
#endif

static arc_buf_t *
dbuf_alloc_arcbuf(dmu_buf_impl_t *db)
{
	spa_t *spa;
	arc_buf_t *buf;

	DB_GET_SPA(&spa, db);
	buf = arc_buf_alloc(spa, db->db.db_size, db, DBUF_GET_BUFC_TYPE(db));
	buf->b_last_dbuf = db;
	return (buf);
}

/*
 * Loan out an arc_buf for read.  Return the loaned arc_buf.
 */
arc_buf_t *
dbuf_loan_arcbuf(dmu_buf_impl_t *db)
{
	arc_buf_t *abuf;
	list_t evict_list;

	dmu_buf_create_user_evict_list(&evict_list);

	mutex_enter(&db->db_mtx);
	if (arc_released(db->db_buf) || refcount_count(&db->db_holds) > 1) {
		int blksz = db->db.db_size;
		spa_t *spa;

		mutex_exit(&db->db_mtx);
		DB_GET_SPA(&spa, db);
		abuf = arc_loan_buf(spa, blksz);
		bcopy(db->db.db_data, abuf->b_data, blksz);
	} else {
		abuf = db->db_buf;
		arc_loan_inuse_buf(abuf, db);
		dbuf_clear_data(db, &evict_list);
		mutex_exit(&db->db_mtx);
	}
	dmu_buf_destroy_user_evict_list(&evict_list);
	return (abuf);
}

uint64_t
dbuf_whichblock(dnode_t *dn, uint64_t offset)
{
	if (dn->dn_datablkshift) {
		return (offset >> dn->dn_datablkshift);
	} else {
		ASSERT3U(offset, <, dn->dn_datablksz);
		return (0);
	}
}

typedef struct dbuf_dirty_record_hole {
	caddr_t src;
	caddr_t dst;
	int size;
} dbuf_dirty_record_hole_t;

typedef struct dbuf_dirty_record_hole_itr {
	/* provided data */
	arc_buf_t *src;
	dbuf_dirty_leaf_record_t *dl;
	/* calculated data */
	dbuf_dirty_range_t *range;
	/* One greater than the last valid offset in the dst buffer */
	int max_offset;
	int hole_start;
	dbuf_dirty_record_hole_t hole;
} dbuf_dirty_record_hole_itr_t;

/*
 * Initialize a dirty record hole iterator for the given dirty leaf dbuf.
 * src_buf must be the initial buffer.
 */
static inline void
dbuf_dirty_record_hole_itr_init(dbuf_dirty_record_hole_itr_t *itr,
    dbuf_dirty_leaf_record_t *dl, arc_buf_t *src_buf)
{
	itr->src = src_buf;
	itr->dl = dl;
	itr->max_offset = MIN(arc_buf_size(src_buf), arc_buf_size(dl->dr_data));
	itr->range = list_head(&dl->write_ranges);
	ASSERT(arc_buf_frozen(dl->dr_data, B_FALSE));
	itr->hole.src = NULL;
	itr->hole.dst = NULL;
	itr->hole.size = 0;
	/* If no ranges exist, the dirty buffer is entirely valid. */
	if (itr->range == NULL) {
		/* Set to the end to return no holes */
		itr->hole_start = itr->max_offset;
	} else if (itr->range->start == 0) {
		itr->hole_start = itr->range->size;
		itr->range = list_next(&itr->dl->write_ranges, itr->range);
	} else
		itr->hole_start = 0;
}

/*
 * Iterate a dirty record, providing the next hole.
 *
 * The hole returned provides direct pointers to the source, destination,
 * and the target size.  A hole is a portion of the dirty record's ARC
 * buffer that does not contain valid data and must be filled in using the
 * initial ARC buffer, which should be entirely valid.
 *
 * Returns NULL If there are no more holes.
 */
static inline dbuf_dirty_record_hole_t *
dbuf_dirty_record_hole_itr_next(dbuf_dirty_record_hole_itr_t *itr)
{

	if (itr->hole_start >= itr->max_offset)
		return (NULL);

	itr->hole.src = (caddr_t)(itr->src->b_data) + itr->hole_start;
	itr->hole.dst = (caddr_t)(itr->dl->dr_data->b_data) + itr->hole_start;
	if (itr->range != NULL) {
		itr->hole.size = MIN(itr->max_offset, itr->range->start) -
		    itr->hole_start;
		itr->hole_start = itr->range->end;
		itr->range = list_next(&itr->dl->write_ranges, itr->range);
	} else {
		itr->hole.size = itr->max_offset - itr->hole_start;
		itr->hole_start = itr->max_offset;
	}
	return (&itr->hole);
}

/*
 * Perform any dbuf arc buffer splits required to guarantee
 * the syncer operates on a stable buffer.  The buffer is provided
 * through its dirty record, syncer_dr.  If this operation is
 * occurring after a resolving read, deferred_split must be TRUE.
 *
 * If the syncer's buffer is currently "in use" in the
 * open transaction group (i.e., there are active holds
 * and db_data still references it), then make a copy
 * before we start the write, so that any modifications
 * from the open txg will not leak into this write.
 *
 * NOTE: This copy does not need to be made for objects only modified
 * in the syncing context (e.g. DNODE_DNODE blocks).
 */
static void
dbuf_syncer_split(dmu_buf_impl_t *db, dbuf_dirty_record_t *syncer_dr,
    boolean_t deferred_split)
{
	if (syncer_dr && (db->db_state & DB_NOFILL) == 0 &&
	    refcount_count(&db->db_holds) > 1 &&
	    syncer_dr->dt.dl.dr_data == db->db_buf) {
		arc_buf_t *buf;

		buf = dbuf_alloc_arcbuf(db);
		bcopy(db->db.db_data, buf->b_data, db->db.db_size);
		if (deferred_split) {
			/*
			 * In the case of a deferred split, the
			 * syncer has already generated a zio that
			 * references the syncer's arc buffer.
			 * Replace the open txg buffer instead.
			 * No activity in the open txg can be
			 * occurring yet.  A reader is waiting
			 * for the resolve to complete, and a
			 * writer hasn't gotten around to creating
			 * a dirty record.  Otherwise this dbuf
			 * would already have been split.
			 */
			dbuf_set_data(db, buf);
		} else {
			/*
			 * The syncer has yet to create a write
			 * zio and since the dbuf may be in the
			 * CACHED state, activity in the open
			 * txg may be occurring.  Switch out
			 * the syncer's dbuf, since it can tolerate
			 * the change.
			 */
			syncer_dr->dt.dl.dr_data = buf;
		}
	}
}

/*
 * Merge write ranges for a dirty record, using buf to fill any holes.
 *
 * This function performs an inverse merge.  The write ranges provided
 * indicate valid data in the dirty leaf's buffer, which means the old
 * buffer has to be copied over exclusive of those ranges.
 */
static void
dbuf_merge_write_ranges(dbuf_dirty_leaf_record_t *dl, arc_buf_t *old_buf)
{
	dbuf_dirty_record_hole_itr_t itr;
	dbuf_dirty_record_hole_t *hole;

	ASSERT3P(dl, !=, NULL);
	/* If there are no write ranges, we're done. */
	if (list_is_empty(&dl->write_ranges))
		return;
	/* If there are write ranges, there must be an ARC buffer. */
	ASSERT(dl->dr_data != NULL);

	/*
	 * We use an iterator here because it simplifies the logic
	 * considerably for this function.
	 */
	dbuf_dirty_record_hole_itr_init(&itr, dl, old_buf);

	while ((hole = dbuf_dirty_record_hole_itr_next(&itr)) != NULL)
		memcpy(hole->dst, hole->src, hole->size);
}

/*
 * Resolve a dbuf using its ranges and the filled ARC buffer provided.
 *
 * This routine is called after a read completes.  The results of the read
 * are stored in the ARC buffer.  It will then merge writes in the order
 * that they occurred, cleaning up write ranges as it goes.
 */
static void
dbuf_resolve_ranges(dmu_buf_impl_t *db, arc_buf_t *buf)
{
	dbuf_dirty_record_t *dr;
	dbuf_dirty_leaf_record_t *dl;
	arc_buf_t *old_buf;

	/* No range data is kept for non data blocks. */
	ASSERT0(db->db_level);

	/*
	 * Start with the oldest dirty record, merging backwards.  For the
	 * first dirty record, the provided ARC buffer is the "old" buffer.
	 *
	 * In turn, the older buffer is copied to the newer one, using an
	 * inverse of the newer one's write ranges.
	 */
	dr = list_tail(&db->db_dirty_records);
	old_buf = buf;
	while (dr != NULL) {
		dl = &dr->dt.dl;
		ASSERT(dl->dr_data);
		dbuf_merge_write_ranges(dl, old_buf);
		/*
		 * Now that we have updated the buffer, freeze it.  However,
		 * if the FILL bit is set, someone else is actively
		 * modifying the current buffer, and will be responsible for
		 * freezing that buffer.
		 */
		if (dl->dr_data != db->db_buf || !(db->db_state & DB_FILL))
			arc_buf_freeze(dl->dr_data);
		dbuf_dirty_record_cleanup_ranges(dr);
		old_buf = dl->dr_data;
		dr = list_prev(&db->db_dirty_records, dr);
	}

	/*
	 * Process any deferred syncer splits now that the buffer contents
	 * are fully valid.
	 */
	dbuf_syncer_split(db, db->db_data_pending, /*deferred_split*/B_TRUE);
}

static void
dbuf_process_buf_sets(dmu_buf_impl_t *db, int err)
{
	dmu_context_node_t *dcn, *next;

	ASSERT(db->db_buf != NULL || err);
	for (dcn = list_head(&db->db_dmu_buf_sets); dcn != NULL; dcn = next) {
		next = list_next(&db->db_dmu_buf_sets, dcn);
		dmu_buf_set_rele(dcn->buf_set, err);
		dmu_context_node_remove(&db->db_dmu_buf_sets, dcn);
	}
}

static void
dbuf_dispatch_override_zio(dbuf_dirty_record_t *dr)
{
	if (dr && dr->dr_override_zio) {
		zio_nowait(dr->dr_override_zio);
		dr->dr_override_zio = NULL;
		DEBUG_COUNTER_INC(override_deferred_write_zios);
	}
}

static void
dbuf_read_complete(dmu_buf_impl_t *db, arc_buf_t *buf, boolean_t is_hole_read)
{
	dbuf_dirty_record_t *oldest_dr = list_tail(&db->db_dirty_records);

	if (db->db_level == 0 && oldest_dr != NULL && !is_hole_read &&
	    !list_is_empty(&oldest_dr->dt.dl.write_ranges)) {
		/*
		 * Fill any holes in the dbuf's dirty records with the
		 * original block we read from disk.
		 *
		 * NOTE: A resolving read can be outstanding for older
		 *	 TXGs at the same time a read completes to satisfy
		 *	 a foreground reader or writer calling
		 *	 dbuf_read_cached().  This only happens when the
		 *	 dbuf has transitioned to DB_UNCACHED via
		 *	 dbuf_free_range().  These foreground operations are
		 *	 always satisfied via dbuf_read_hole(), which sets
		 *	 is_hole_read to prevent foreground operations from
		 *	 mistakenly filling holes in older TXGs.
		 */

		dbuf_resolve_ranges(db, buf);

		if (db->db_state == DB_READ) {
			DBUF_STATE_CHANGE(db, =, DB_CACHED,
			    "resolve of records with only READ set");
		} else if (db->db_state & DB_READ) {
			ASSERT(db->db_state == (DB_READ|DB_FILL));
			DBUF_STATE_CHANGE(db, &=, ~DB_READ,
			    "resolve of records with READ state bit set");
		}

		arc_discard_buf(buf, db);

		if (oldest_dr->dr_zio) {
			ASSERT(oldest_dr == db->db_data_pending);
			zio_nowait(oldest_dr->dr_zio);
			DEBUG_COUNTER_INC(syncer_deferred_write_zios);
		}
		dbuf_dispatch_override_zio(oldest_dr);
		DEBUG_COUNTER_INC(resolves_completed);
	} else if (db->db_state == DB_READ) {
		/*
		 * Read with no dirty data.  Use the buffer we
		 * read and transition to DB_CACHED.
		 */
		dbuf_set_data(db, buf);
		DBUF_STATE_CHANGE(db, =, DB_CACHED,
		    "read completed with no dirty records");
	} else {
		/*
		 * The block was filled or freed before the read completed.
		 * If it was filled, it is either CACHED or FILL.  If it was
		 * freed, it is CACHED and already zero filled.
		 */
		ASSERT(db->db_state == DB_CACHED || db->db_state == DB_FILL);
		/*
		 * The filler may still be running, but it can only have one
		 * dirty record; otherwise, a resolve must occur.
		 */
		ASSERT(db->db_state != DB_FILL || db->db_dirtycnt == 1);

		/* Regardless, the frontend must already be populated. */
		ASSERT(db->db_buf != NULL);
		arc_discard_buf(buf, db);
	}
	dbuf_process_buf_sets(db, /*err*/0);
}

static void
dbuf_read_done(zio_t *zio, arc_buf_t *buf, void *vdb)
{
	dmu_buf_impl_t *db = vdb;
	dbuf_dirty_record_t *dr;

	ASSERT(db->db_blkid != DMU_BONUS_BLKID);

	mutex_enter(&db->db_mtx);

	dprintf_dbuf(db, "%s: zio=%p arc=%p\n", __func__, zio, buf);

	/* Any reads or writes must have a hold on this dbuf */
	ASSERT(refcount_count(&db->db_holds) > 0);

	if (zio == NULL || zio->io_error == 0) {
		/* Read succeeded. */
		dbuf_read_complete(db, buf, /*is_hole_read*/B_FALSE);
	} else {
		/* Read failed. */
		if (db->db_dirtycnt > 0) {
			/*
			 * The failure of this read has already been
			 * communicated to the user by the zio pipeline.
			 * Limit our losses to just the data we can't
			 * read by filling any holes in our dirty records
			 * with zeros.
			 */ 
			bzero(buf->b_data, arc_buf_size(buf));
			arc_buf_freeze(buf);
			dbuf_read_complete(db, buf, /*is_hole_read*/B_FALSE);
			atomic_add_64(&dirty_writes_lost, 1);
		} else {
			ASSERT3P(db->db_buf, ==, NULL);
			db->db_state = DB_UNCACHED;
			DBUF_STATE_CHANGE(db, =, DB_UNCACHED, "read failed");
			dbuf_process_buf_sets(db, zio->io_error);
		}
		VERIFY(arc_buf_remove_ref(buf, db));
	}
	cv_broadcast(&db->db_changed);
	dbuf_rele_and_unlock(db, NULL);
}

/*
 * Shortcut for performing reads on bonus dbufs.  Returns whether any action
 * was taken.
 */
static boolean_t
dbuf_read_bonus(dmu_buf_impl_t *db, dnode_t *dn, uint32_t *flags)
{
	int bonuslen = MIN(dn->dn_bonuslen, dn->dn_phys->dn_bonuslen);

	if (db->db_blkid != DMU_BONUS_BLKID)
		return B_FALSE;

	ASSERT(MUTEX_HELD(&db->db_mtx));
	ASSERT(DB_DNODE_HELD(db));
	ASSERT3U(bonuslen, <=, db->db.db_size);
	db->db.db_data = zio_buf_alloc(DN_MAX_BONUSLEN);
	arc_space_consume(DN_MAX_BONUSLEN, ARC_SPACE_OTHER);
	if (bonuslen < DN_MAX_BONUSLEN)
		bzero(db->db.db_data, DN_MAX_BONUSLEN);
	if (bonuslen)
		bcopy(DN_BONUS(dn->dn_phys), db->db.db_data, bonuslen);
	DBUF_STATE_CHANGE(db, =, DB_CACHED, "bonus buffer filled");
	return (B_TRUE);
}

/*
 * Handle reads on dbufs that are holes, if necessary.  This function
 * requires that the dbuf's mutex is held, and if it performs any action, it
 * drops the mutex.  Returns whether any action was taken.
 */
static boolean_t
dbuf_read_hole(dmu_buf_impl_t *db, dnode_t *dn, uint32_t *flags)
{
	int is_hole;

	ASSERT(MUTEX_HELD(&db->db_mtx));

	/*
	 * If the dbuf isn't UNCACHED, then presumably the caller is trying
	 * to perform a resolving read.
	 */
	if (db->db_state != DB_UNCACHED) {
		ASSERT(db->db_level == 0);
		ASSERT(db->db_state & (DB_PARTIAL|DB_FILL|DB_READ));
		ASSERT(db->db_dirtycnt > 0);
		return (B_FALSE);
	}

	is_hole = db->db_blkptr == NULL || BP_IS_HOLE(db->db_blkptr);
	/*
	 * For level 0 blocks only, if the above check fails:
	 * Recheck BP_IS_HOLE() after dnode_block_freed() in case dnode_sync()
	 * processes the delete record and clears the bp while we are waiting
	 * for the dn_mtx (resulting in a "no" from block_freed).
	 */
	if (!is_hole && db->db_level == 0)
		is_hole = dnode_block_freed(dn, db->db_blkid) ||
		    BP_IS_HOLE(db->db_blkptr);

	if (is_hole) {
		arc_buf_t *buf;

		buf = dbuf_alloc_arcbuf(db);
		bzero(buf->b_data, db->db.db_size);
		DBUF_STATE_CHANGE(db, =, DB_READ, "hole read satisfied");
		dbuf_read_complete(db, buf, /*is_hole_read*/B_TRUE);
		return (B_TRUE);
	}
	return (B_FALSE);
}

static void
dbuf_read_cached_done(zio_t *zio, arc_buf_t *buf, void *priv)
{
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)priv;

	if (buf != NULL) {
		ASSERT(arc_buf_frozen(buf, B_TRUE) && !arc_released(buf));
		db->db_state = DB_READ; /* for read_complete */
		dbuf_read_complete(db, buf, /*is_hole_read*/B_FALSE);
	}
}

/*
 * Actually read (or issue I/O for) a dbuf's block.
 *
 * Flags will be modified to include DB_RF_CACHED if the call returns with
 * the dbuf cached.
 *
 * The DB_RF_CACHED_ONLY flag has the effect of performing a cached-only
 * read.  Only in this case will the dbuf mutex be retained.
 */
static void
dbuf_read_impl(dmu_buf_impl_t *db, zio_t *zio, uint32_t *flags)
{
	dnode_t *dn;
	spa_t *spa;
	zbookmark_t zb;
	uint32_t aflags = ARC_NOWAIT;

	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);
	ASSERT(!refcount_is_zero(&db->db_holds));
	ASSERT(MUTEX_HELD(&db->db_mtx));
	ASSERT(db->db_state == DB_UNCACHED || (db->db_state & DB_PARTIAL));

	if (dbuf_read_bonus(db, dn, flags) || dbuf_read_hole(db, dn, flags)) {
		DB_DNODE_EXIT(db);
		*flags |= DB_RF_CACHED;
		if ((*flags & DB_RF_CACHED_ONLY) == 0)
			mutex_exit(&db->db_mtx);
		return;
	}

	spa = dn->dn_objset->os_spa;

	/* Check to see if a caller only wants cached buffers. */
	if (*flags & DB_RF_CACHED_ONLY) {
		ASSERT(db->db_state == DB_UNCACHED && db->db_buf == NULL &&
		    db->db_dirtycnt == 0);
		aflags = ARC_CACHED_ONLY;
		(void) arc_read(/*pio*/NULL, spa, db->db_blkptr,
		    dbuf_read_cached_done, db, /*priority*/0, /*zio_flags*/0,
		    &aflags, /*zb*/NULL);

		if (aflags & ARC_CACHED)
			*flags |= DB_RF_CACHED;
		DB_DNODE_EXIT(db);
		/* Cache lookups never drop the dbuf mutex. */
		return;
	}

	DB_DNODE_EXIT(db);

	DBUF_STATE_CHANGE(db, =, DB_READ, "read issued");
	mutex_exit(&db->db_mtx);

	/*
	 * db_blkptr is protected by both the dbuf mutex and the associated
	 * struct_rwlock.  The caller must acquire struct_rwlock before
	 * reads that may sleep without the dbuf mutex held.
	 */
	ASSERT(RW_LOCK_HELD(&dn->dn_struct_rwlock));

	if (DBUF_IS_L2CACHEABLE(db))
		aflags |= ARC_L2CACHE;
	if (DBUF_IS_L2COMPRESSIBLE(db))
		aflags |= ARC_L2COMPRESS;

	SET_BOOKMARK(&zb, db->db_objset->os_dsl_dataset ?
	    db->db_objset->os_dsl_dataset->ds_object : DMU_META_OBJSET,
	    db->db.db_object, db->db_level, db->db_blkid);

	dbuf_add_ref(db, NULL);

	(void) arc_read(zio, spa, db->db_blkptr,
	    dbuf_read_done, db, ZIO_PRIORITY_SYNC_READ,
	    (*flags & DB_RF_CANFAIL) ? ZIO_FLAG_CANFAIL : ZIO_FLAG_MUSTSUCCEED,
	    &aflags, &zb);
	if (aflags & ARC_CACHED)
		*flags |= DB_RF_CACHED;
}

/*
 * Find a dbuf's block in the ARC, if it's there.  Calling this is equivalent
 * to calling dbuf_read, but only if the block is already in the cache.
 *
 * This function only applies to level 0 blocks, and requires the dbuf mutex.
 * Returns whether an ARC hit occurred.
 */
static boolean_t
dbuf_read_cached(dmu_buf_impl_t *db, dnode_t *dn)
{
	int rflags = DB_RF_CACHED_ONLY;
	boolean_t held = RW_WRITE_HELD(&dn->dn_struct_rwlock);

	ASSERT(DB_DNODE_HELD(db));

	/* Make sure read_impl doesn't change its contract with us. */
	ASSERT(MUTEX_HELD(&db->db_mtx));
	dbuf_read_impl(db, NULL, &rflags);
	ASSERT(MUTEX_HELD(&db->db_mtx));

	return ((rflags & DB_RF_CACHED) != 0);
}

int
dbuf_read(dmu_buf_impl_t *db, zio_t *zio, uint32_t flags)
{
	int err = 0;
	int havepzio = (zio != NULL);
	int prefetch;
	dnode_t *dn;

	/*
	 * We don't have to hold the mutex to check db_state because it
	 * can't be freed while we have a hold on the buffer.
	 */
	ASSERT(!refcount_is_zero(&db->db_holds));

	if (db->db_state == DB_NOFILL)
		return (SET_ERROR(EIO));

	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);
	if ((flags & DB_RF_HAVESTRUCT) == 0)
		rw_enter(&dn->dn_struct_rwlock, RW_READER);

	prefetch = db->db_level == 0 && db->db_blkid != DMU_BONUS_BLKID &&
	    (flags & DB_RF_NOPREFETCH) == 0 && dn != NULL &&
	    DBUF_IS_CACHEABLE(db);

	mutex_enter(&db->db_mtx);
	if (db->db_state == DB_CACHED) {
		mutex_exit(&db->db_mtx);
		if (prefetch)
			dmu_zfetch(&dn->dn_zfetch, db->db.db_offset,
			    db->db.db_size, TRUE);
		if ((flags & DB_RF_HAVESTRUCT) == 0)
			rw_exit(&dn->dn_struct_rwlock);
		DB_DNODE_EXIT(db);
	} else if (db->db_state & (DB_UNCACHED|DB_PARTIAL)) {
		spa_t *spa = dn->dn_objset->os_spa;

		if (zio == NULL)
			zio = zio_root(spa, NULL, NULL, ZIO_FLAG_CANFAIL);
		dbuf_read_impl(db, zio, &flags);

		/* dbuf_read_impl has dropped db_mtx for us */

		if (prefetch)
			dmu_zfetch(&dn->dn_zfetch, db->db.db_offset,
			    db->db.db_size, flags & DB_RF_CACHED);

		if ((flags & DB_RF_HAVESTRUCT) == 0)
			rw_exit(&dn->dn_struct_rwlock);
		DB_DNODE_EXIT(db);

		if (!havepzio)
			err = zio_wait(zio);
	} else {
		/*
		 * Another reader came in while the dbuf was in flight
		 * between UNCACHED and CACHED.  Either a writer will finish
		 * writing the buffer (sending the dbuf to CACHED) or the
		 * first reader's request will reach the read_done callback
		 * and send the dbuf to CACHED.  Otherwise, a failure
		 * occurred and the dbuf went to UNCACHED.
		 */
		mutex_exit(&db->db_mtx);
		if (prefetch)
			dmu_zfetch(&dn->dn_zfetch, db->db.db_offset,
			    db->db.db_size, TRUE);
		if ((flags & DB_RF_HAVESTRUCT) == 0)
			rw_exit(&dn->dn_struct_rwlock);
		DB_DNODE_EXIT(db);

		/* Skip the wait per the caller's request. */
		if ((flags & DB_RF_NEVERWAIT) == 0) {
			mutex_enter(&db->db_mtx);
			while (db->db_state & (DB_READ|DB_FILL)) {
				ASSERT(db->db_state == DB_READ ||
				    (flags & DB_RF_HAVESTRUCT) == 0);
				cv_wait(&db->db_changed, &db->db_mtx);
			}
			if (db->db_state == DB_UNCACHED)
				err = SET_ERROR(EIO);
			mutex_exit(&db->db_mtx);
		}
	}

	ASSERT(err || havepzio || db->db_state == DB_CACHED);
	return (err);
}

/*
 * Signal that the dirty record is about to be re-dirtied after sync.
 *
 * This function is used to notify, if necessary, that a dbuf is about
 * to be dirtied again after having an immediate write via dmu_sync().
 */
void
dbuf_unoverride(dbuf_dirty_record_t *dr)
{
	dmu_buf_impl_t *db = dr->dr_dbuf;
	blkptr_t *bp = &dr->dt.dl.dr_overridden_by;
	uint64_t txg = dr->dr_txg;

	ASSERT(MUTEX_HELD(&db->db_mtx));
	ASSERT(dr->dt.dl.dr_override_state != DR_IN_DMU_SYNC);
	ASSERT(db->db_level == 0);

	if (db->db_blkid == DMU_BONUS_BLKID ||
	    dr->dt.dl.dr_override_state == DR_NOT_OVERRIDDEN)
		return;

	ASSERT(db->db_data_pending != dr);

	/* free this block */
	if (!BP_IS_HOLE(bp) && !dr->dt.dl.dr_nopwrite) {
		spa_t *spa;

		DB_GET_SPA(&spa, db);
		zio_free(spa, txg, bp);
	}
	dr->dt.dl.dr_override_state = DR_NOT_OVERRIDDEN;
	dr->dt.dl.dr_nopwrite = B_FALSE;

	/*
	 * Release the already-written buffer, so we leave it in
	 * a consistent dirty state.  Note that all callers are
	 * modifying the buffer, so they will immediately do
	 * another (redundant) arc_release().  Therefore, leave
	 * the buf thawed to save the effort of freezing &
	 * immediately re-thawing it.
	 */
	arc_release(dr->dt.dl.dr_data, db);
}

/*
 * Disassociate the frontend for any older transaction groups of a
 * dbuf that is inside a range being freed.  The primary purpose is to
 * ensure that the state of any dirty records affected by the operation
 * remain consistent.
 */
static void
dbuf_free_range_disassociate_frontend(dmu_buf_impl_t *db, dnode_t *dn,
    dmu_tx_t *tx, list_t *evict_list_p)
{
	dbuf_dirty_record_t *dr;

	dr = list_head(&db->db_dirty_records);
	tmpprintf("%s db %p dr %p holds %lu dirties %d txg %llu\n",
	    __func__, db, dr, refcount_count(&db->db_holds),
	    db->db_dirtycnt, tx->tx_txg);

	if (dr == NULL)
		return;

	if (dr->dr_txg == tx->tx_txg) {
		/*
		 * This buffer is "in-use", re-adjust the file size to reflect
		 * that this buffer may contain new data when we sync.
		 */
		if (db->db_blkid != DMU_SPILL_BLKID &&
		    db->db_blkid > dn->dn_maxblkid)
			dn->dn_maxblkid = db->db_blkid;
		/* Handle intermediate dmu_sync() calls. */
		dbuf_unoverride(dr);

		/*
		 * If this buffer is still waiting on data for a RMW merge, that
		 * data no longer applies to this buffer.  Transition to cached.
		 */
		dbuf_dirty_record_cleanup_ranges(dr);
	} else {
		if (db->db_state & DB_PARTIAL) {
			/*
			 * Schedule resolution for the older transaction
			 * group's dirty record before we change the dbuf's
			 * state and lose track of the PARTIAL state.
			 */
			dbuf_transition_to_read(db);
		}
		/* Disassociate the frontend if necessary. */
		if (dr->dt.dl.dr_data == db->db_buf) {
			arc_buf_t *buf;

			buf = dbuf_alloc_arcbuf(db);
			if (refcount_count(&db->db_holds) > db->db_dirtycnt) {

				/*
				 * Frontend being referenced by a user, but
				 * this dirty record has yet to be processed
				 * by the syncer.
				 */
				ASSERT(dr != db->db_data_pending);
				if (db->db_state & DB_READ) {
					/*
					 * The reader has yet to access the
					 * frontend (it must wait for the      
					 * READ->CACHED transition), so it
					 * is safe to replace the frontend.
					 */
					dbuf_set_data(db, buf);
				} else {
					/*
					 * A reader is accessing the frontend,
					 * so we cannot replace it.
					 * Disassociate by replacing the
					 * buffer used for future syncer
					 * operations.
					 */
					bcopy(db->db.db_data, buf->b_data,
					    db->db.db_size);
					dr->dt.dl.dr_data = buf;
				}
			} else {
				/*
				 * Foreground is currently unreferenced, but
				 * a future access that results in a READ
				 * will confuse in-progress resolution of
				 * dirty records for older transactions.
				 * Provide a buffer so any future consumers
				 * will see a dbuf in the CACHED state.
				 */
				dbuf_set_data(db, buf);
			}
		}
	}
}

/*
 * Dirty level 1 blocks for a free_range operation.  Returns whether an
 * indirect block is processed.
 */
static boolean_t
dbuf_free_range_indirects(dnode_t *dn, dmu_buf_impl_t *db, uint64_t start,
    uint64_t end, dmu_tx_t *tx)
{
	dbuf_dirty_record_t *dr;
	int epbs = dn->dn_indblkshift - SPA_BLKPTRSHIFT;
	uint64_t first_l1 = start >> epbs;
	uint64_t last_l1 = end >> epbs;

	if (db->db_level == 0)
		return (B_FALSE);

	if (db->db_level == 1 && IN_RANGE(first_l1, db->db_blkid, last_l1)) {
		mutex_enter(&db->db_mtx);
		dr = list_head(&db->db_dirty_records);
		if (dr != NULL && dr->dr_txg < tx->tx_txg) {
			dbuf_add_ref(db, FTAG);
			mutex_exit(&db->db_mtx);
			dbuf_will_dirty(db, tx);
			dbuf_rele(db, FTAG);
		} else {
			mutex_exit(&db->db_mtx);
		}
	}
	return (B_TRUE);
}

static boolean_t
dbuf_free_range_already_freed(dmu_buf_impl_t *db)
{
	/* XXX add comment about why these are OK */
	if (db->db_state == DB_UNCACHED || db->db_state == DB_NOFILL ||
	    db->db_state == DB_EVICTING) {
		ASSERT(db->db.db_data == NULL);
		mutex_exit(&db->db_mtx);
		return (B_TRUE);
	}
	return (B_FALSE);
}

static boolean_t
dbuf_free_range_filler_will_free(dmu_buf_impl_t *db)
{
	if (db->db_state & DB_FILL) {
		/*
		 * If the buffer is currently being filled, then its
		 * contents cannot be directly cleared.  Signal the filler
		 * to have dbuf_fill_done perform the clear just before
		 * transitioning the buffer to the CACHED state.
		 */
		db->db_freed_in_flight = TRUE;
		mutex_exit(&db->db_mtx);
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * If a dbuf has no users, clear it.  Returns whether it was cleared.
 */
static boolean_t
dbuf_clear_successful(dmu_buf_impl_t *db, list_t *evict_list_p)
{

	if (refcount_count(&db->db_holds) == 0) {
		/* All consumers are finished, so evict the buffer */
		ASSERT(db->db_buf != NULL);
		dbuf_clear(db, evict_list_p);
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Free a range of data blocks in a dnode.  The start and end are inclusive.
 *
 * Evict (if it's unreferenced) or clear (if it's referenced) any level-0
 * data blocks in the free range, so that any future readers will find
 * empty blocks.  Also, if we happen across any level-1 dbufs in the
 * range that have not already been marked dirty, mark them dirty so
 * they stay in memory.
 */
void
dbuf_free_range(dnode_t *dn, uint64_t start, uint64_t end, dmu_tx_t *tx)
{
	dmu_buf_impl_t *db, *db_next;
	list_t evict_list;

	ASSERT(RW_WRITE_HELD(&dn->dn_struct_rwlock));

	dmu_buf_create_user_evict_list(&evict_list);

	if (end > dn->dn_maxblkid && (end != DMU_SPILL_BLKID))
		end = dn->dn_maxblkid;

	dprintf_dnode(dn, "start=%llu end=%llu\n", start, end);
	mutex_enter(&dn->dn_dbufs_mtx);
	for (db = list_head(&dn->dn_dbufs); db; db = db_next) {
		dbuf_dirty_record_t *dr;

		db_next = list_next(&dn->dn_dbufs, db);
		ASSERT(db->db_blkid != DMU_BONUS_BLKID);

		if (dbuf_free_range_indirects(dn, db, start, end, tx))
			continue;
		if (!IN_RANGE(start, db->db_blkid, end))
			continue;
		mutex_enter(&db->db_mtx);
		if (dbuf_undirty(db, tx)) {
			/* mutex has been dropped and dbuf destroyed */
			continue;
		}

		dr = list_head(&db->db_dirty_records);
		if (dr && dr->dr_txg != tx->tx_txg)
			dr = NULL;
		DBUF_VERIFY(db);
		if (dbuf_free_range_already_freed(db) ||
		    dbuf_free_range_filler_will_free(db) ||
		    dbuf_clear_successful(db, &evict_list))
			continue; /* db_mtx already exited */

		/*
		 * The goal is to make the data that is visible in the current
		 * transaction group all zeros, while preserving the data
		 * as seen in any earlier transaction groups.
		 */
		dbuf_free_range_disassociate_frontend(db, dn, tx, &evict_list);
		if (db->db_buf == NULL) {
			ASSERT(db->db_state == DB_READ);
			dbuf_set_data(db, dbuf_alloc_arcbuf(db));
		} else {
			ASSERT(db->db_buf != NULL);
			arc_release(db->db_buf, db);
		}
		bzero(db->db.db_data, db->db.db_size);
		arc_buf_freeze(db->db_buf);
		/* Dispatch an override zio if one is waiting. */
		dbuf_dispatch_override_zio(dr);
		DBUF_STATE_CHANGE(db, =, DB_CACHED, "zeroed by free");
		dbuf_process_buf_sets(db, /*err*/0);
		cv_broadcast(&db->db_changed);
		mutex_exit(&db->db_mtx);
		/* Process one dbuf at a time to reduce memory pressure. */
		dmu_buf_process_user_evicts(&evict_list);
	}
	mutex_exit(&dn->dn_dbufs_mtx);
	dmu_buf_destroy_user_evict_list(&evict_list);
}

static int
dbuf_block_freeable(dmu_buf_impl_t *db)
{
	dsl_dataset_t *ds = db->db_objset->os_dsl_dataset;
	dbuf_dirty_record_t *dr;
	uint64_t birth_txg = 0;

	/*
	 * We don't need any locking to protect db_blkptr:
	 * If it's syncing, then db_dirty_records will have
	 * entries, so we'll ignore db_blkptr.
	 */
	ASSERT(MUTEX_HELD(&db->db_mtx));
	dr = list_head(&db->db_dirty_records);
	if (dr != NULL)
		birth_txg = dr->dr_txg;
	else if (db->db_blkptr)
		birth_txg = db->db_blkptr->blk_birth;

	/*
	 * If we don't exist or are in a snapshot, we can't be freed.
	 * Don't pass the bp to dsl_dataset_block_freeable() since we
	 * are holding the db_mtx lock and might deadlock if we are
	 * prefetching a dedup-ed block.
	 */
	if (birth_txg)
		return (ds == NULL ||
		    dsl_dataset_block_freeable(ds, NULL, birth_txg));
	else
		return (FALSE);
}

static void
dbuf_dirty_record_truncate_ranges(dbuf_dirty_record_t *dr, int new_size)
{
	dbuf_dirty_leaf_record_t *dl;
	dbuf_dirty_range_t *range;

	ASSERT(MUTEX_HELD(&dr->dr_dbuf->db_mtx));
	if (dr->dr_dbuf->db_level != 0)
		return;

	dl = &dr->dt.dl;
	for (;;) {
		range = list_tail(&dl->write_ranges);

		if (range->start >= new_size) {
			list_remove(&dl->write_ranges, range);
			kmem_free(range, sizeof(dbuf_dirty_range_t));
			continue;
		}

		/*
		 * Update the last range that could be affected by
		 * this truncation.  Its size changes only if it
		 * extends past the end of the buffer's new size.
		 */
		range->end = MIN(new_size, range->end);
		range->size = range->end - range->size;
		break;
	}
}

void
dbuf_new_size(dmu_buf_impl_t *db, int size, dmu_tx_t *tx)
{
	arc_buf_t *buf, *old_buf;
	int osize = db->db.db_size;
	arc_buf_contents_t type = DBUF_GET_BUFC_TYPE(db);
	dnode_t *dn;

	ASSERT(db->db_blkid != DMU_BONUS_BLKID);

	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);

	/* XXX does *this* func really need the lock? */
	ASSERT(RW_WRITE_HELD(&dn->dn_struct_rwlock));

	/*
	 * This call to dbuf_will_dirty() with the dn_struct_rwlock held
	 * is OK, because there can be no other references to the db
	 * when we are changing its size, so no concurrent DB_FILL can
	 * be happening.
	 */
	/*
	 * XXX we should be doing a dbuf_read, checking the return
	 * value and returning that up to our callers
	 */
	/* XXX this needs to be made nonblocking */
	dbuf_will_dirty(db, tx);

	/* create the data buffer for the new block */
	buf = arc_buf_alloc(dn->dn_objset->os_spa, size, db, type);

	/* copy old block data to the new block */
	old_buf = db->db_buf;
	bcopy(old_buf->b_data, buf->b_data, MIN(osize, size));
	/* zero the remainder */
	if (size > osize)
		bzero((uint8_t *)buf->b_data + osize, size - osize);

	mutex_enter(&db->db_mtx);
	dbuf_set_data(db, buf);
	VERIFY(arc_buf_remove_ref(old_buf, db));
	db->db.db_size = size;

	if (db->db_level == 0) {
		dbuf_dirty_record_t *dr;

		dr = list_head(&db->db_dirty_records);
		ASSERT3U(dr->dr_txg, ==, tx->tx_txg);
		dr->dt.dl.dr_data = buf;
	}
	mutex_exit(&db->db_mtx);

	dnode_willuse_space(dn, size-osize, tx);
	DB_DNODE_EXIT(db);
}

void
dbuf_release_bp(dmu_buf_impl_t *db)
{
	objset_t *os;

	DB_GET_OBJSET(&os, db);
	ASSERT(dsl_pool_sync_context(dmu_objset_pool(os)));
	ASSERT(arc_released(os->os_phys_buf) ||
	    list_link_active(&os->os_dsl_dataset->ds_synced_link));
	ASSERT(db->db_parent == NULL || arc_released(db->db_parent->db_buf));

	(void) arc_release(db->db_buf, db);
}

/*
 * State of the current dirtying process.  Dirtying requires keeping a lot
 * of state available, so using a struct to access it keeps the code sane.
 */
typedef struct dbuf_dirty_state {
	dmu_buf_impl_t *db;		/* Dbuf being dirtied. */
	dmu_tx_t *tx;			/* Transaction to dirty. */
	dnode_t *dn;			/* The dbuf's dnode. */
	dbuf_dirty_record_t *insert_pt;	/* DR to insert new DR after. */
	dbuf_dirty_record_t *txg_dr;	/* Dirty record for this txg. */
	boolean_t txg_already_dirty;	/* This txg already dirty? */
	boolean_t do_free_accounting;	/* Free accounting needed? */
	list_t evict_list;		/* Dbuf user eviction list. */

	/* The below only apply to leaf blocks. */
	arc_buf_t *fill_buf;		/* Already-filled optional buffer. */
	int offset;			/* Offset of the upcoming write. */
	int size;			/* Size of the upcoming write. */
} dbuf_dirty_state_t;

static void
dbuf_new_dirty_record_accounting(dbuf_dirty_state_t *dds)
{
	dnode_t *dn = dds->dn;
	dmu_tx_t *tx = dds->tx;
	dmu_buf_impl_t *db = dds->db;
	objset_t *os = dn->dn_objset;

	/*
	 * Only valid if not already dirty in this transaction group.
	 */
	DNODE_VERIFY_DIRTYCTX(dn, tx);

	ASSERT3U(dn->dn_nlevels, >, db->db_level);
	ASSERT((dn->dn_phys->dn_nlevels == 0 && db->db_level == 0) ||
	    dn->dn_phys->dn_nlevels > db->db_level ||
	    DN_NEXT_LEVEL(dn, tx->tx_txg) > db->db_level ||
	    DN_NEXT_LEVEL(dn, tx->tx_txg - 1) > db->db_level ||
	    DN_NEXT_LEVEL(dn, tx->tx_txg - 2) > db->db_level);

	/*
	 * We should only be dirtying in syncing context if it's the
	 * mos or we're initializing the os or it's a special object.
	 * However, we are allowed to dirty in syncing context provided
	 * we already dirtied it in open context.  Hence we must make
	 * this assertion only if we're not already dirty.
	 */
	ASSERT(!dmu_tx_is_syncing(tx) ||
	    DMU_OBJECT_IS_SPECIAL(dn->dn_object) ||
	    os->os_dsl_dataset == NULL || BP_IS_HOLE(os->os_rootbp));
	ASSERT(db->db.db_size != 0);

	dprintf_dbuf(db, "size=%llx\n", (u_longlong_t)db->db.db_size);

	if (db->db_blkid != DMU_BONUS_BLKID) {
		/*
		 * Update the accounting.
		 * Note: we delay "free accounting" until after we drop
		 * the db_mtx.  This keeps us from grabbing other locks
		 * (and possibly deadlocking) in bp_get_dsize() while
		 * also holding the db_mtx.
		 */
		dnode_willuse_space(dn, db->db.db_size, tx);
		if (db->db_blkid != DMU_SPILL_BLKID)
			dds->do_free_accounting = dbuf_block_freeable(db);
	}
}

static dbuf_dirty_record_t *
dbuf_dirty_record_create(dbuf_dirty_state_t *dds)
{
	dbuf_dirty_record_t *dr;

	ASSERT(MUTEX_HELD(&dds->db->db_mtx));
	ASSERT(DB_DNODE_HELD(dds->db));
	ASSERT((dr = list_head(&dds->db->db_dirty_records)) == NULL ||
	    dr->dr_txg != dds->tx->tx_txg);

	dbuf_new_dirty_record_accounting(dds);

	ASSERT(dds->txg_dr == NULL);
	dr = kmem_zalloc(sizeof(dbuf_dirty_record_t), KM_SLEEP);
	dr->dr_dbuf = dds->db;
	dr->dr_txg = dds->tx->tx_txg;
	dds->txg_dr = dr;

	return (dr);
}

static void
dbuf_dirty_record_register(dbuf_dirty_state_t *dds)
{

	ASSERT(dds->txg_dr != NULL);
	list_insert_after(&dds->db->db_dirty_records, dds->insert_pt,
	    dds->txg_dr);

	/* This buffer is now part of this txg */
	dbuf_add_ref(dds->db, (void *)(uintptr_t)dds->tx->tx_txg);
	dds->db->db_dirtycnt += 1;
	ASSERT3U(dds->db->db_dirtycnt, <=, TXG_CONCURRENT_STATES);
}

static void
dbuf_dirty_record_create_indirect(dbuf_dirty_state_t *dds)
{
	dbuf_dirty_record_t *dr;

	dr = dbuf_dirty_record_create(dds);
	mutex_init(&dr->dt.di.dr_mtx, NULL, MUTEX_DEFAULT, NULL);
	list_create(&dr->dt.di.dr_children,
	    sizeof (dbuf_dirty_record_t),
	    offsetof(dbuf_dirty_record_t, dr_dirty_node));
	dbuf_dirty_record_register(dds);
}

static void
dbuf_dirty_record_update_leaf(dbuf_dirty_state_t *dds)
{
	if (dds->db->db_blkid == DMU_BONUS_BLKID)
		dds->txg_dr->dt.dl.dr_data = dds->db->db.db_data;
	else
		dds->txg_dr->dt.dl.dr_data = dds->db->db_buf;
}

static void
dbuf_dirty_record_register_as_leaf(dbuf_dirty_state_t *dds)
{
	dbuf_dirty_record_t *dr = dds->txg_dr;
	dmu_buf_impl_t *db = dds->db;

	dbuf_dirty_record_update_leaf(dds);
	dprintf_dbuf(db, "%s: dr_data=%p\n", __func__, dr->dt.dl.dr_data);
	list_create(&dr->dt.dl.write_ranges, sizeof(dbuf_dirty_range_t),
	    offsetof(dbuf_dirty_range_t, write_range_link));
	dbuf_dirty_record_register(dds);
}

static void
dbuf_dirty_record_create_nofill(dbuf_dirty_state_t *dds)
{
	dbuf_dirty_record_t *dr;
	
	(void) dbuf_dirty_record_create(dds);
	dbuf_dirty_record_register_as_leaf(dds);
}

void
dbuf_dirty_verify(dmu_buf_impl_t *db, dmu_tx_t *tx)
{
#ifdef ZFS_DEBUG
	dnode_t *dn = DB_DNODE(db);
	dbuf_dirty_record_t *dr;

	/* Ensure that this dbuf has a transaction group and a hold */
	ASSERT(tx->tx_txg != 0);
	ASSERT(!refcount_is_zero(&db->db_holds));
	DMU_TX_VERIFY_DIRTY_BUF(tx, db);

	dr = list_head(&db->db_dirty_records);
	ASSERT(dr == NULL || dr->dr_txg <= tx->tx_txg ||
	    db->db.db_object == DMU_META_DNODE_OBJECT);

	/*
	 * Shouldn't dirty a regular buffer in syncing context.  Private
	 * objects may be dirtied in syncing context, but only if they
	 * were already pre-dirtied in open context.
	 */
	ASSERT(!dmu_tx_is_syncing(tx) ||
	    BP_IS_HOLE(dn->dn_objset->os_rootbp) ||
	    DMU_OBJECT_IS_SPECIAL(dn->dn_object) ||
	    dn->dn_objset->os_dsl_dataset == NULL);

	DNODE_VERIFY_DIRTYCTX(dn, tx);
#endif
}

/*
 * Enter a dbuf-dirtying function.  This function should only be called once
 * per dirty.
 *
 * This function's primary purpose is to compute state that only needs to be
 * computed once per dirty call.  Call dbuf_dirty_compute_state if the
 * function drops the mutex, for things that require re-computing.
 */
static void
dbuf_dirty_enter(dbuf_dirty_state_t *dds, dmu_buf_impl_t *db, dmu_tx_t *tx)
{
	dbuf_dirty_record_t *dr;

	memset(dds, 0, sizeof(*dds));
	dds->db = db;
	dds->tx = tx;

	dmu_buf_create_user_evict_list(&dds->evict_list);
	DB_DNODE_ENTER(db);
	dds->dn = DB_DNODE(db);

	mutex_enter(&db->db_mtx);
}

/*
 * Compute the current dbuf dirty state.  The dbuf mutex must be held before
 * this function is called, and afterwards, must not be dropped except by
 * dbuf_dirty_exit().  If this is not possible, the intention was to allow a
 * dbuf_dirty function to re-invoke this function after an action that might
 * drop the mutex, and before continuing.  Additional work may be needed.
 */
static void
dbuf_dirty_compute_state(dbuf_dirty_state_t *dds)
{
	dmu_buf_impl_t *db = dds->db;
	dmu_tx_t *tx = dds->tx;
	dbuf_dirty_record_t *dr, *newest;

	/* Only one filler allowed at a time. */
	while (db->db_state & DB_FILL) {
		ASSERT(db->db_level == 0);
		cv_wait(&db->db_changed, &db->db_mtx);
	}

	dbuf_dirty_verify(db, tx);
	if (db->db_blkid == DMU_SPILL_BLKID)
		dds->dn->dn_have_spill = B_TRUE;
	dnode_set_dirtyctx(dds->dn, tx, db);

	newest = list_head(&db->db_dirty_records);

	/* Only the mdn object may dirty an older txg.  */
	ASSERT(newest == NULL || newest->dr_txg <= tx->tx_txg ||
	    db->db.db_object == DMU_META_DNODE_OBJECT);

	dds->insert_pt = NULL; /* Insert at head. */
	for (dr = newest; dr != NULL && dr->dr_txg > tx->tx_txg;
	    dr = list_next(&db->db_dirty_records, dr))
		dds->insert_pt = dr;

	if (dr != NULL && dr->dr_txg == tx->tx_txg)
		dds->txg_dr = dr;

	/*
	 * Cache whether this TX already has a dirty record, so that upon exit,
	 * additional work can be done after dropping the dbuf mutex.  This
	 * information is useful elsewhere, too.
	 */
	dds->txg_already_dirty = (dds->txg_dr != NULL);
}

static void dbuf_dirty_parent(dbuf_dirty_state_t *dds);

/*
 * Exit a dbuf-dirtying function.  See dbuf_dirty.  The primary purpose is
 * to verify a consistent state upon completing a dirty operation, then drop
 * the mutex and dirty parent dbufs.
 *
 * It is also a good time to update free accounting.
 *
 * NOTE: This should only be called once in a dbuf-dirtying function.
 */
static void
dbuf_dirty_exit(dbuf_dirty_state_t *dds)
{
	dmu_buf_impl_t *db = dds->db;
	void *front = (db->db_blkid == DMU_BONUS_BLKID) ? db->db.db_data :
	    db->db_buf;

	ASSERT(db->db_level != 0 || dds->txg_dr->dt.dl.dr_data == front);
	ASSERT(dds->txg_dr->dr_txg == dds->tx->tx_txg);

	mutex_exit(&db->db_mtx);
	dmu_buf_destroy_user_evict_list(&dds->evict_list);

	if (!dds->txg_already_dirty) {
		if (dds->do_free_accounting) {
			/* NB: This only applies to non-SPILL/BONUS blocks. */
			blkptr_t *bp = db->db_blkptr;
			objset_t *os = dds->dn->dn_objset;
			int64_t willfree = (bp && !BP_IS_HOLE(bp)) ?
			    bp_get_dsize(os->os_spa, bp) : db->db.db_size;
			/*
			 * This is only a guess -- if the dbuf is dirty
			 * in a previous txg, we don't know how much
			 * space it will use on disk yet.  We should
			 * really have the struct_rwlock to access
			 * db_blkptr, but since this is just a guess,
			 * it's OK if we get an odd answer.
			 */
			ddt_prefetch(os->os_spa, bp);
			dnode_willuse_space(dds->dn, -willfree, dds->tx);
		}
		dbuf_dirty_parent(dds);
	}

	DB_DNODE_EXIT(db);
}

/*
 * Dirty a nofill buffer.  See dbuf_dirty.
 *
 * NOFILL buffers are similar to regular leaf buffers only in the sense that
 * they create dirty records that contain ARC buffers in each txg.  They
 * don't need any frontend manipulation.
 */
dbuf_dirty_record_t *
dbuf_dirty_nofill(dmu_buf_impl_t *db, dmu_tx_t *tx)
{
	dbuf_dirty_state_t dds;

	ASSERT(db->db_level == 0);
	ASSERT(db->db_blkid != DMU_BONUS_BLKID);
	ASSERT(db->db_state & (DB_UNCACHED|DB_NOFILL|DB_CACHED));

	dbuf_dirty_enter(&dds, db, tx);
	DBUF_STATE_CHANGE(db, =, DB_NOFILL, "allocating NOFILL buffer");
	dbuf_clear_data(db, &dds.evict_list);
	dbuf_dirty_compute_state(&dds);

	if (dds.txg_already_dirty)
		/*
		 * Reset immediate write sync state if needed.
		 * XXX: Is this really needed for NOFILL buffers?
		 */
		dbuf_unoverride(dds.txg_dr);
	else
		dbuf_dirty_record_create_nofill(&dds);

	dbuf_dirty_exit(&dds);
	return (dds.txg_dr);
}

/*
 * Dirty an indirect block.  See dbuf_dirty.
 *
 * Indirect blocks are always completely rewritten, so they don't need any
 * complex frontend manipulation.
 */
static dbuf_dirty_record_t *
dbuf_dirty_indirect(dmu_buf_impl_t *db, dmu_tx_t *tx)
{
	dbuf_dirty_state_t dds;

	dbuf_dirty_enter(&dds, db, tx);
	dbuf_dirty_compute_state(&dds);

	if (!dds.txg_already_dirty)
		dbuf_dirty_record_create_indirect(&dds);

	dbuf_dirty_exit(&dds);
	return (dds.txg_dr);
}

/*
 * Dirty the dbuf's parent.
 *
 * NOTE: If the dnode's struct_rwlock is not held, it will be grabbed and
 *       dropped within this function.
 */
static void
dbuf_dirty_parent(dbuf_dirty_state_t *dds)
{
	dnode_t *dn = dds->dn;
	dmu_buf_impl_t *db = dds->db;
	dmu_tx_t *tx = dds->tx;
	dbuf_dirty_record_t *dr = dds->txg_dr;

	int drop_struct_lock = FALSE;
	int txgoff = tx->tx_txg & TXG_MASK;

	if (db->db_blkid == DMU_BONUS_BLKID ||
	    db->db_blkid == DMU_SPILL_BLKID) {
		mutex_enter(&dn->dn_mtx);
		ASSERT(!list_link_active(&dr->dr_dirty_node));
		list_insert_tail(&dn->dn_dirty_records[txgoff], dr);
		mutex_exit(&dn->dn_mtx);
		dnode_setdirty(dn, tx);
		return;
	}

	if (!RW_WRITE_HELD(&dn->dn_struct_rwlock)) {
		rw_enter(&dn->dn_struct_rwlock, RW_READER);
		drop_struct_lock = TRUE;
	}

	if (db->db_level == 0) {
		dnode_new_blkid(dn, db->db_blkid, tx, drop_struct_lock);
		ASSERT(dn->dn_maxblkid >= db->db_blkid);
	}

	if (db->db_level+1 < dn->dn_nlevels) {
		/* The dbuf's parent is an indirect block */
		dmu_buf_impl_t *parent = db->db_parent;
		dbuf_dirty_record_t *di;
		int parent_held = FALSE;

		/* Get a hold on the parent before dropping struct_rwlock */
		if (db->db_parent == NULL || db->db_parent == dn->dn_dbuf) {
			int epbs = dn->dn_indblkshift - SPA_BLKPTRSHIFT;

			parent = dbuf_hold_level(dn, db->db_level+1,
			    db->db_blkid >> epbs, FTAG);
			ASSERT(parent != NULL);
			parent_held = TRUE;
		}
		if (drop_struct_lock)
			rw_exit(&dn->dn_struct_rwlock);

		ASSERT3U(db->db_level+1, ==, parent->db_level);
		di = dbuf_dirty_indirect(parent, tx);
		if (parent_held)
			dbuf_rele(parent, FTAG);

		/*
		 * Update the dirty record to add this dbuf to its parent's
		 * dirty record's list of dirty children.  The indirect
		 * mutex could be conditionally acquired, but doing so is
		 * unlikely to save any effort in most cases.  Acquiring it
		 * unconditionally keeps this path clean of apparent LORs.
		 */
		mutex_enter(&di->dt.di.dr_mtx);
		mutex_enter(&db->db_mtx);
		/*  possible race with dbuf_undirty() */
		if (list_head(&db->db_dirty_records) == dr ||
		    dn->dn_object == DMU_META_DNODE_OBJECT) {
			ASSERT3U(di->dr_txg, ==, tx->tx_txg);
			ASSERT(!list_link_active(&dr->dr_dirty_node));
			list_insert_tail(&di->dt.di.dr_children, dr);
			dr->dr_parent = di;
		}
		mutex_exit(&db->db_mtx);
		mutex_exit(&di->dt.di.dr_mtx);
	} else {
		/* The dbuf's parent is the dnode */
		ASSERT(db->db_level+1 == dn->dn_nlevels);
		ASSERT(db->db_blkid < dn->dn_nblkptr);
		ASSERT(db->db_parent == NULL || db->db_parent == dn->dn_dbuf);
		/*
		 * Update the dnode's list of dirty records to include this
		 * dbuf's dirty record.
		 */
		mutex_enter(&dn->dn_mtx);
		ASSERT(!list_link_active(&dr->dr_dirty_node));
		list_insert_tail(&dn->dn_dirty_records[txgoff], dr);
		mutex_exit(&dn->dn_mtx);
		if (drop_struct_lock)
			rw_exit(&dn->dn_struct_rwlock);
	}

	dnode_setdirty(dn, tx);
}

static void
dbuf_dirty_record_check_ranges(dbuf_dirty_record_t *dr)
{
#ifdef ZFS_DEBUG
	dbuf_dirty_leaf_record_t *dl;
	dbuf_dirty_range_t *prev, *cur, *next;

	if (!(zfs_flags & ZFS_DEBUG_DBUF_VERIFY))
		return;

	dl = &dr->dt.dl;

	prev = next = NULL;
	for (cur = list_head(&dl->write_ranges); cur != NULL;
	    prev = cur, cur = next) {
		next = list_next(&dl->write_ranges, cur);
		ASSERT(prev == NULL || cur->start > prev->end);
		ASSERT(next == NULL || cur->end < next->start);
	}
#endif
}

/*
 * Record a write range for the associated dirty record.
 */
static void
dbuf_dirty_record_add_range(dbuf_dirty_record_t *dr, int offset, int size)
{
	dbuf_dirty_range_t *next_range, *old_range, *range;
	dbuf_dirty_leaf_record_t *dl;
	dmu_buf_impl_t *db;

	dl = &dr->dt.dl;
	db = dr->dr_dbuf;

	/* Write ranges do not apply to indirect blocks. */
	ASSERT(db->db_level == 0);
	ASSERT(MUTEX_HELD(&db->db_mtx));

	/* Optimization: clear the ranges if the incoming range fills. */
	if (offset == 0 && size == db->db.db_size) {
		dbuf_dirty_record_cleanup_ranges(dr);
		goto out;
	}

	range = kmem_zalloc(sizeof(dbuf_dirty_range_t), KM_SLEEP);
	range->start = offset;
	range->size = size;
	range->end = offset + size;

	/*
	 * This loop acts as an accumulator, merging dirty ranges if they
	 * overlap or are adjacent, and in so doing leaving behind only one
	 * range.  But if the new range must be inserted separately, it will
	 * do so using the old range as a marker.
	 */
	for (old_range = list_head(&dl->write_ranges);
	    old_range != NULL && old_range->start <= range->end;
	    old_range = next_range) {
		next_range = list_next(&dl->write_ranges, old_range);
		if (range->start <= old_range->end &&
		    range->end >= old_range->start) {
			old_range->start = MIN(range->start, old_range->start);
			old_range->end = MAX(range->end, old_range->end);
			old_range->size = old_range->end - old_range->start;
			list_remove(&dl->write_ranges, old_range);
			DEBUG_REFCOUNT_DEC(dirty_ranges_in_flight);
			kmem_free(range, sizeof(dbuf_dirty_range_t));
			range = old_range;
		}
	}

	/* If the writer will finish filling, go directly to DB_FILL. */
	if (range->start == 0 && range->size == db->db.db_size) {
		kmem_free(range, sizeof(dbuf_dirty_range_t));
	} else {
		/* If old_range is NULL, this does a list_insert_tail(). */
		list_insert_before(&dl->write_ranges, old_range, range);
		DEBUG_REFCOUNT_INC(dirty_ranges_in_flight);
		DEBUG_COUNTER_INC(dirty_ranges_total);
	}

	dbuf_dirty_record_check_ranges(dr);

out:
	if (dr->dr_dbuf->db_state & (DB_READ|DB_PARTIAL))
		if (list_is_empty(&dr->dt.dl.write_ranges))
			DBUF_STATE_CHANGE(db, =, DB_FILL, "complete filler");
}

static void
dbuf_dirty_set_data(dbuf_dirty_state_t *dds)
{
	arc_buf_t *buf = dds->fill_buf;
	if (buf == NULL)
		buf = dbuf_alloc_arcbuf(dds->db);
	dbuf_set_data(dds->db, buf);
}

static void
dbuf_dirty_leaf_with_existing_frontend(dbuf_dirty_state_t *dds)
{
	dmu_buf_impl_t *db = dds->db;
	int size = db->db.db_size;
	dbuf_dirty_record_t *newest = list_head(&db->db_dirty_records);
	boolean_t old_txg_is_frontend = !dds->txg_already_dirty &&
	    newest != NULL && newest->dt.dl.dr_data == db->db_buf;
	arc_buf_t *fill_buf = dds->fill_buf;

	ASSERT(fill_buf == NULL || fill_buf != db->db_buf);
	ASSERT(refcount_count(&db->db_holds) > db->db_dirtycnt);

	/* Reset any immediate write that has occurred. */
	if (dds->txg_already_dirty)
		dbuf_unoverride(dds->txg_dr);

	/* If the old txg's record owns the frontend, give it its own copy. */
	if (old_txg_is_frontend) {
		if (newest == db->db_data_pending) {
			/*
			 * The syncer or holder normally disassociate.  But if
			 * the syncer is performing a deferred resolve, then
			 * it will not disassociate until the resolve
			 * completes.  Since the syncer has already
			 * scheduled its write with its buffer, we must
			 * disassociate by replacing the frontend.
			 */
			ASSERT(db->db_state & (DB_READ|DB_PARTIAL));
			ASSERT(db->db_dirtycnt == 1);
			dbuf_dirty_set_data(dds);
		} else {
			newest->dt.dl.dr_data = dbuf_alloc_arcbuf(db);
			bcopy(db->db.db_data, newest->dt.dl.dr_data->b_data,
			    size);
			arc_release(db->db_buf, db);
			if (fill_buf) {
				bcopy(fill_buf->b_data, db->db.db_data, size);
				ASSERT(arc_released(fill_buf));
				VERIFY(arc_buf_remove_ref(fill_buf, db));
			}
		}
		return;
	}

	/* We have a filled buffer and already own the current frontend. */
	if (fill_buf) {
		arc_release(db->db_buf, db);
		bcopy(fill_buf->b_data, db->db.db_data, size);
		ASSERT(arc_released(fill_buf));
		VERIFY(arc_buf_remove_ref(fill_buf, db));
		return;
	}

	/* Frontend not owned by anybody.  Notify that it will be modified. */
	ASSERT(newest == NULL || fill_buf == NULL);
	if (dds->txg_already_dirty) {
		/* Already released on initial dirty, so just thaw. */
		ASSERT(arc_released(db->db_buf));
		arc_buf_thaw(db->db_buf);
	} else
		arc_release(db->db_buf, db);
}

static void
dbuf_dirty_record_create_leaf(dbuf_dirty_state_t *dds)
{
	dmu_buf_impl_t *db = dds->db;
	dbuf_dirty_record_t *dr;

	dr = dbuf_dirty_record_create(dds);

	/*
	 * If this block was marked to be freed in this txg, revert that
	 * change.  Note that db_freed_in_flight may have already been
	 * processed, so it can't be checked here.
	 */
	if (db->db_blkid != DMU_SPILL_BLKID) {
		mutex_enter(&dds->dn->dn_mtx);
		dnode_clear_range(dds->dn, db->db_blkid, /*nblks*/1, dds->tx);
		mutex_exit(&dds->dn->dn_mtx);
		db->db_freed_in_flight = FALSE;
	}
	dbuf_dirty_record_register_as_leaf(dds);
}

static void
dbuf_dirty_leaf_common(dbuf_dirty_state_t *dds)
{
	dmu_buf_impl_t *db = dds->db;

	if (db->db_buf == NULL)
		dbuf_dirty_set_data(dds);
	else
		dbuf_dirty_leaf_with_existing_frontend(dds);
	ASSERT(arc_released(db->db_buf) && arc_buf_frozen(db->db_buf, B_FALSE));

	if (!dds->txg_already_dirty)
		dbuf_dirty_record_create_leaf(dds);
	else
		dbuf_dirty_record_update_leaf(dds);

	if (db->db_state != DB_CACHED)
		dbuf_dirty_record_add_range(dds->txg_dr, dds->offset,
		    dds->size);
}

dbuf_dirty_record_t *
dbuf_dirty_record_create_bonus(dbuf_dirty_state_t *dds)
{
	dmu_buf_impl_t *db = dds->db;
	dbuf_dirty_record_t *newest = list_head(&db->db_dirty_records);
	boolean_t last_txg_is_frontend = newest != NULL &&
	    newest->dt.dl.dr_data == db->db.db_data;
	dbuf_dirty_record_t *dr;

	if (last_txg_is_frontend) {
		newest->dt.dl.dr_data = zio_buf_alloc(DN_MAX_BONUSLEN);
		arc_space_consume(DN_MAX_BONUSLEN, ARC_SPACE_OTHER);
		bcopy(db->db.db_data, newest->dt.dl.dr_data, DN_MAX_BONUSLEN);
	}
	dr = dbuf_dirty_record_create(dds);
	dbuf_dirty_record_register_as_leaf(dds);
	return (dr);
}

/*
 * Dirty a dbuf belonging to a meta-dnode.  See dbuf_dirty.
 *
 * Dbufs belonging to the meta-dnode object are allowed to dirty in older
 * transaction groups.  Additionally, they will always be overwritten in
 * each transaction group, which means no complex frontend manipulation.
 * simplifies the logic considerably compared to normal leaf objects.
 */
dbuf_dirty_record_t *
dbuf_dirty_mdn_object(dmu_buf_impl_t *db, dmu_tx_t *tx)
{
	dbuf_dirty_state_t dds;

	ASSERT(db->db_level == 0);
	ASSERT(db->db_blkid != DMU_BONUS_BLKID);

	dbuf_dirty_enter(&dds, db, tx);
	dbuf_dirty_compute_state(&dds);

	if (db->db_buf == NULL)
		dbuf_set_data(db, dbuf_alloc_arcbuf(db));

	if (dds.txg_already_dirty)
		dbuf_unoverride(dds.txg_dr);
	else
		(void) dbuf_dirty_record_create_leaf(&dds);

	dbuf_dirty_exit(&dds);
	return (dds.txg_dr);
}

/*
 * Dirty a bonus dbuf.  See dbuf_dirty.
 *
 * Bonus buffers are special in the sense that they do not use ARC buffers,
 * but instead occupy space inside the dnode physical block.  The dbuf
 * layer's primary role is to provide a transactional mechanism for updating
 * this special dnode section.  Underlying bonus blocks therefore always use
 * special zio buffers, and never share information between transactions.
 */
dbuf_dirty_record_t *
dbuf_dirty_bonus(dmu_buf_impl_t *db, dmu_tx_t *tx)
{
	dbuf_dirty_state_t dds;

	ASSERT(db->db_blkid == DMU_BONUS_BLKID);
	/* Can't dirty a bonus buffer without first reading it. */
	ASSERT(db->db_state == DB_CACHED);
	dbuf_dirty_enter(&dds, db, tx);
	dbuf_dirty_compute_state(&dds);

	if (!dds.txg_already_dirty)
		(void) dbuf_dirty_record_create_bonus(&dds);

	dbuf_dirty_exit(&dds);
	return (dds.txg_dr);
}

/*
 * Handle potential Copy-On-Write (COW) faults.
 *
 * This function's primary purpose is to optimize dirtying behavior that are
 * likely to involve COW faults.
 */
static void
dbuf_dirty_handle_fault(dbuf_dirty_state_t *dds)
{
	dmu_buf_impl_t *db = dds->db;

	ASSERT(db->db_level == 0);
	if (db->db_state & DB_PARTIAL) {
		dbuf_dirty_record_t *dr = list_head(&db->db_dirty_records);
		if (dr->dr_txg != dds->tx->tx_txg) {
			/*
			 * The newest dirty record's transaction group has
			 * closed.  Since COW fault resolution can't be
			 * avoided, there is no benefit to waiting until the
			 * dirty record reaches the syncer.  Start
			 * asynchronous fault resolution now.
			 */
			dbuf_transition_to_read(db);
		}
	} else if (db->db_state == DB_UNCACHED) {
		int write_end = dds->offset + dds->size;

		if (dds->offset != 0 && write_end != db->db.db_size) {
			/*
			 * Immediately start resolving a COW fault if we start
			 * writing inside the block rather than either at the
			 * beginning (forward) or end (backward).  Future
			 * writes are unlikely to fill this dbuf.
			 */
			dbuf_transition_to_read(db);
		} else if (dds->size != db->db.db_size) {
			/*
			 * If this dirty won't fill the buffer, see if a
			 * previous version is in the ARC.  This skips the
			 * partial buffer bookkeeping that would otherwise
			 * be necessary.
			 */
			dbuf_read_cached(db, dds->dn);
		}
	}
}

/*
 * Common dbuf_dirty_enter() replacement for leaf blocks.
 */
void
dbuf_dirty_leaf_enter(dbuf_dirty_state_t *dds,
    dmu_buf_impl_t *db, dmu_tx_t *tx, int offset, int size)
{

	dbuf_dirty_enter(dds, db, tx);
	dds->offset = offset;
	dds->size = size;
	/*
	 * Handle COW faults prior to computing the dirty state, since
	 * transitioning to read drops the lock.
	 */
	dbuf_dirty_handle_fault(dds);
	dbuf_dirty_compute_state(dds);
}

/*
 * Dirty a regular leaf block.  See dbuf_dirty.
 *
 * This function handles dirtying all user data blocks.
 */
dbuf_dirty_record_t *
dbuf_dirty_leaf(dmu_buf_impl_t *db, dmu_tx_t *tx, int offset, int size)
{
	dbuf_dirty_state_t dds;

	ASSERT(db->db.db_object != DMU_META_DNODE_OBJECT);
	ASSERT(db->db_blkid != DMU_BONUS_BLKID);
	ASSERT(db->db_level == 0);

	dbuf_dirty_leaf_enter(&dds, db, tx, offset, size);

	if (db->db_state == DB_UNCACHED)
		DBUF_STATE_CHANGE(db, =, (DB_PARTIAL|DB_FILL),
		    "notifying of initial partial fill");
	else if (db->db_state & (DB_READ|DB_PARTIAL))
		DBUF_STATE_CHANGE(db, |=, DB_FILL,
		    "notifying of followup partial fill");
	dbuf_dirty_leaf_common(&dds);

	dbuf_dirty_exit(&dds);
	return (dds.txg_dr);
}

/*
 * Dirty a regular leaf block with a filled ARC buffer.  See dbuf_dirty.
 *
 * This function is identical to dbuf_dirty_leaf, except that it doesn't
 * have to handle partial fills, since it is always provided an already
 * filled buffer that is the write data for the transaction.
 */
dbuf_dirty_record_t *
dbuf_dirty_with_arcbuf(dmu_buf_impl_t *db, dmu_tx_t *tx, arc_buf_t *fill_buf)
{
	dbuf_dirty_state_t dds;

	ASSERT(db->db_level == 0);

	dbuf_dirty_leaf_enter(&dds, db, tx, 0, db->db.db_size);
	dds.fill_buf = fill_buf;

	if (db->db_state != DB_CACHED)
		DBUF_STATE_CHANGE(db, =, DB_FILL, "assigning filled buffer");
	dbuf_dirty_leaf_common(&dds);

	dbuf_dirty_exit(&dds);
	return (dds.txg_dr);
}

/*
 * Dirty a DMU buffer.
 *
 * This function is merely a dispatcher.  Different types of dbufs require
 * different actions in different scenarios.  However, each dbuf_dirty
 * implementing function should follow the same basic order:
 *
 * 1. dbuf_dirty_enter (grab the dbuf mutex)
 * 2. Do any pre-dirty optimizations or fixups needed.
 * *** Beyond this point, the dbuf mutex must always be held. ***
 * 3. dbuf_dirty_compute_state (compute the basic dbuf_dirty state)
 * 4. Change the dbuf state as applicable
 * 5. Make the frontend (db->db_buf) usable by the dirty record for this txg.
 * 6. Create or update this txg's dirty record, if needed.
 * 7. dbuf_dirty_exit, which triggers dirtying parent dbufs if this dbuf was
 *    not already dirty in this txg.
 *
 * NOTE: The point of having separate functions is to reduce the difficulty
 *       of understanding what happens to each type of dbuf in a dirty.
 */
dbuf_dirty_record_t *
dbuf_dirty(dmu_buf_impl_t *db, dmu_tx_t *tx)
{
	if (db->db_blkid == DMU_BONUS_BLKID) {
		return (dbuf_dirty_bonus(db, tx));
	} else if (db->db_level == 0) {
		if (db->db.db_object == DMU_META_DNODE_OBJECT)
			return (dbuf_dirty_mdn_object(db, tx));
		else
			return (dbuf_dirty_leaf(db, tx, 0, db->db.db_size));
	} else {
		return (dbuf_dirty_indirect(db, tx));
	}
}

/*
 * Cleanup a dirty record's write ranges as necessary.
 *
 * XXX: This should be replaced with a larger dbuf_dirty_record_destroy()
 *      that cleans up an entire dirty record.
 */
void
dbuf_dirty_record_cleanup_ranges(dbuf_dirty_record_t *dr)
{
	dbuf_dirty_leaf_record_t *dl;
	dbuf_dirty_range_t *range;

	/* Write ranges do not apply to indirect blocks */
	if (dr->dr_dbuf->db_level != 0)
		return;

	/* Remove any write range entries left behind. */
	dl = &dr->dt.dl;
	while ((range = list_remove_head(&dl->write_ranges)) != NULL) {
		kmem_free(range, sizeof(dbuf_dirty_range_t));
		DEBUG_REFCOUNT_DEC(dirty_ranges_in_flight);
	}
}

/* XXX: refactor dbuf_undirty_*() into dbuf_undirty(). */
static void
dbuf_undirty_bonus(dbuf_dirty_record_t *dr)
{
	dmu_buf_impl_t *db = dr->dr_dbuf;

	if (dr->dt.dl.dr_data != db->db.db_data) {
		zio_buf_free(dr->dt.dl.dr_data, DN_MAX_BONUSLEN);
		arc_space_return(DN_MAX_BONUSLEN, ARC_SPACE_OTHER);
	}
	db->db_data_pending = NULL;
	ASSERT(list_next(&db->db_dirty_records, dr) == NULL);
	list_remove(&db->db_dirty_records, dr);
	kmem_free(dr, sizeof(dbuf_dirty_record_t));
	ASSERT(db->db_dirtycnt > 0);
	db->db_dirtycnt -= 1;
}

static void
dbuf_undirty_leaf(dbuf_dirty_record_t *dr)
{
	dmu_buf_impl_t *db = dr->dr_dbuf;

	ASSERT(db->db_blkid != DMU_BONUS_BLKID);
	if (db->db_state == DB_NOFILL)
		return;

	if (dr->dt.dl.dr_data != db->db_buf) {
		/*
		 * What we wrote is already out of date, so
		 * just free the ARC buffer.
		 */
		VERIFY(arc_buf_remove_ref(dr->dt.dl.dr_data, db));
	} else if (!arc_released(db->db_buf)) {
		/*
		 * Our dbuf hasn't already been evicted, so
		 * register a callback to clean it up once
		 * its ARC buffer is released.
		 */
		arc_set_callback(db->db_buf, dbuf_do_evict, db);
	}
}

static void
dbuf_undirty_indirect(dbuf_dirty_record_t *dr)
{
	dnode_t *dn;
	dmu_buf_impl_t *db = dr->dr_dbuf;

	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);
	ASSERT(list_head(&dr->dt.di.dr_children) == NULL);
	/*
	 * The size of an indirect block must match what its
	 * associated dnode thinks it should be.
	 */
	ASSERT3U(db->db.db_size, ==, 1<<dn->dn_phys->dn_indblkshift);
	/*
	 * If the dbuf's block pointer is not a hole, evict it when
	 * its last ARC buffer hold has been released.
	 */
	if (!BP_IS_HOLE(db->db_blkptr)) {
		int epbs = dn->dn_phys->dn_indblkshift - SPA_BLKPTRSHIFT;
		ASSERT3U(BP_GET_LSIZE(db->db_blkptr), ==, db->db.db_size);
		ASSERT3U(dn->dn_phys->dn_maxblkid >> (db->db_level * epbs), >=,
		    db->db_blkid);
		arc_set_callback(db->db_buf, dbuf_do_evict, db);
	}
	DB_DNODE_EXIT(db);
	mutex_destroy(&dr->dt.di.dr_mtx);
	list_destroy(&dr->dt.di.dr_children);
}

static void
dbuf_undirty_write(dbuf_dirty_record_t *dr, uint64_t txg)
{
	dmu_buf_impl_t *db = dr->dr_dbuf;

	ASSERT(!list_link_active(&dr->dr_dirty_node));
	ASSERT(dr->dr_txg == txg);
	/* There should be no older dirty records. */
	ASSERT(list_next(&db->db_dirty_records, dr) == NULL);
	list_remove(&db->db_dirty_records, dr);

#ifdef ZFS_DEBUG
	if (db->db_blkid == DMU_SPILL_BLKID) {
		dnode_t *dn;

		DB_DNODE_ENTER(db);
		dn = DB_DNODE(db);
		ASSERT(dn->dn_phys->dn_flags & DNODE_FLAG_SPILL_BLKPTR);
		ASSERT(!(BP_IS_HOLE(db->db_blkptr)) &&
		    db->db_blkptr == &dn->dn_phys->dn_spill);
		DB_DNODE_EXIT(db);
	}
#endif

	/* Clean up the dirty record. */
	if (db->db_level == 0) {
		dbuf_undirty_leaf(dr);
		dbuf_dirty_record_cleanup_ranges(dr);
		list_destroy(&dr->dt.dl.write_ranges);
	} else {
		dbuf_undirty_indirect(dr);
	}
	kmem_free(dr, sizeof (dbuf_dirty_record_t));

	cv_broadcast(&db->db_changed);
	ASSERT(db->db_dirtycnt > 0);
	db->db_dirtycnt -= 1;
	db->db_data_pending = NULL;
}

/*
 * Undirty a buffer in the transaction group referenced by the given
 * transaction.  Return whether this evicted the dbuf.
 */
static boolean_t
dbuf_undirty(dmu_buf_impl_t *db, dmu_tx_t *tx)
{
	dnode_t *dn;
	uint64_t txg = tx->tx_txg;
	dbuf_dirty_record_t *dr;
	list_t evict_list;

	ASSERT(txg != 0);
	ASSERT(db->db_blkid != DMU_BONUS_BLKID);
	ASSERT0(db->db_level);
	ASSERT(MUTEX_HELD(&db->db_mtx));

	dmu_buf_create_user_evict_list(&evict_list);
	/*
	 * If this buffer is not dirty in this transaction
	 * group, we're done.
	 */
	dr = dbuf_get_dirty_record_for_txg(db, txg);
	if (dr == NULL) {
		dmu_buf_destroy_user_evict_list(&evict_list);
		return (B_FALSE);
	}
	ASSERT(dr->dr_txg == txg);
	ASSERT(dr->dr_dbuf == db);

	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);

	/*
	 * Note:  This code will probably work even if there are concurrent
	 * holders, but it is untested in that scenerio, as the ZPL and
	 * ztest have additional locking (the range locks) that prevents
	 * that type of concurrent access.
	 */
	ASSERT3U(refcount_count(&db->db_holds), ==, db->db_dirtycnt);

	dprintf_dbuf(db, "size=%llx\n", (u_longlong_t)db->db.db_size);

	ASSERT(db->db.db_size != 0);

	/* XXX would be nice to fix up *_space_towrite[] */

	list_remove(&db->db_dirty_records, dr);

	/*
	 * Note that there are three places in dbuf_dirty()
	 * where this dirty record may be put on a list.
	 * Make sure to do a list_remove corresponding to
	 * every one of those list_insert calls.
	 */
	if (dr->dr_parent) {
		mutex_enter(&dr->dr_parent->dt.di.dr_mtx);
		list_remove(&dr->dr_parent->dt.di.dr_children, dr);
		mutex_exit(&dr->dr_parent->dt.di.dr_mtx);
	} else if (db->db_blkid == DMU_SPILL_BLKID ||
	    db->db_level+1 == dn->dn_nlevels) {
		ASSERT(db->db_blkptr == NULL || db->db_parent == dn->dn_dbuf);
		mutex_enter(&dn->dn_mtx);
		list_remove(&dn->dn_dirty_records[txg & TXG_MASK], dr);
		mutex_exit(&dn->dn_mtx);
	}
	DB_DNODE_EXIT(db);

	if (db->db_state != DB_NOFILL) {
		dbuf_unoverride(dr);

		ASSERT(db->db_buf != NULL);
		ASSERT(dr->dt.dl.dr_data != NULL);
		if (dr->dt.dl.dr_data != db->db_buf)
			VERIFY(arc_buf_remove_ref(dr->dt.dl.dr_data, db));
	}
	dbuf_dirty_record_cleanup_ranges(dr);
	if (db->db_level == 0)
		list_destroy(&dr->dt.dl.write_ranges);
	kmem_free(dr, sizeof (dbuf_dirty_record_t));

	ASSERT(db->db_dirtycnt > 0);
	db->db_dirtycnt -= 1;

	if (refcount_remove(&db->db_holds, (void *)(uintptr_t)txg) == 0) {
		arc_buf_t *buf = db->db_buf;

		tmpprintf("%s db %p clearing\n", __func__, db);
		ASSERT(db->db_state == DB_NOFILL || arc_released(buf));
		dbuf_clear_data(db, &evict_list);
		VERIFY(arc_buf_remove_ref(buf, db));
		dbuf_evict(db, &evict_list);
		dmu_buf_destroy_user_evict_list(&evict_list);
		return (B_TRUE);
	}

	dmu_buf_destroy_user_evict_list(&evict_list);
	return (B_FALSE);
}

#pragma weak dmu_buf_will_dirty = dbuf_will_dirty
void
dbuf_will_dirty(dmu_buf_impl_t *db, dmu_tx_t *tx)
{
	int rf = DB_RF_MUST_SUCCEED | DB_RF_NOPREFETCH;

	ASSERT(tx->tx_txg != 0);
	ASSERT(!refcount_is_zero(&db->db_holds));

	DB_DNODE_ENTER(db);
	if (RW_WRITE_HELD(&DB_DNODE(db)->dn_struct_rwlock))
		rf |= DB_RF_HAVESTRUCT;
	DB_DNODE_EXIT(db);
	(void) dbuf_read(db, NULL, rf);
	/* Already CACHED or UNCACHED at this point */
	(void) dbuf_dirty(db, tx);
}

/*
 * Issue an async read that will eventually transition a dbuf into the
 * CACHED state.  The dbuf's mutex must be held.
 *
 * Upon return, the dbuf will either be in the READ (async READ
 * pending), or CACHED (read satisfied by a cache hit or zero fill for
 * an object hole) state.
 *
 * NOTE: The dbuf's mutex is dropped temporarilly while the read is
 *       scheduled.  Caller's must reverify if necessary any state
 *       protected by the dbuf mutex.
 */
void
dbuf_transition_to_read(dmu_buf_impl_t *db)
{
	int rf = DB_RF_MUST_SUCCEED | DB_RF_NOPREFETCH | DB_RF_NEVERWAIT;
	dnode_t *dn;
	zio_t *zio = NULL;

	ASSERT(MUTEX_HELD(&db->db_mtx));
	ASSERT(db->db_state & (DB_PARTIAL|DB_UNCACHED));

	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);
	if (RW_WRITE_HELD(&dn->dn_struct_rwlock))
		rf |= DB_RF_HAVESTRUCT;
	zio = zio_root(dn->dn_objset->os_spa, NULL, NULL,
	    ZIO_FLAG_MUSTSUCCEED);
	DB_DNODE_EXIT(db);

	mutex_exit(&db->db_mtx);
	(void) dbuf_read(db, zio, rf);
	(void) zio_nowait(zio);
	mutex_enter(&db->db_mtx);
}

#pragma weak dmu_buf_will_dirty_range = dbuf_will_dirty_range
/*
 * Signal intent to dirty a subset of the buffer.
 *
 * XXX: This needs to be merged into dbuf_will_dirty().
 */
void
dbuf_will_dirty_range(dmu_buf_impl_t *db, dmu_tx_t *tx, int offset, int size)
{
	dbuf_dirty_record_t *dr;

	ASSERT(tx->tx_txg != 0);
	ASSERT(!refcount_is_zero(&db->db_holds));
	ASSERT(db->db_level == 0);
	ASSERT(db->db_blkid != DMU_SPILL_BLKID);
	ASSERT(db->db_blkid != DMU_BONUS_BLKID);
#ifdef ZFS_DEBUG
	{
		dnode_t *dn;

		DB_DNODE_ENTER(db);
		dn = DB_DNODE(db);
		ASSERT(!DMU_OBJECT_IS_SPECIAL(dn->dn_object));
		DB_DNODE_EXIT(db);
	}
#endif

	dbuf_dirty_leaf(db, tx, offset, size);
}

void
dmu_buf_will_not_fill(dmu_buf_t *db_fake, dmu_tx_t *tx)
{
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)db_fake;

	dbuf_dirty_nofill(db, tx);
}

void
dmu_buf_will_fill(dmu_buf_t *db_fake, dmu_tx_t *tx)
{
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)db_fake;

	ASSERT(db->db_blkid != DMU_BONUS_BLKID);
	ASSERT(tx->tx_txg != 0);
	ASSERT(db->db_level == 0);
	ASSERT(!refcount_is_zero(&db->db_holds));

	ASSERT(db->db.db_object != DMU_META_DNODE_OBJECT ||
	    dmu_tx_private_ok(tx));

	/* Wait for another filler to finish. */
	while (db->db_state & DB_FILL)
		cv_wait(&db->db_changed, &db->db_mtx);

	dbuf_dirty_leaf(db, tx, 0, db->db.db_size);
}

#pragma weak dmu_buf_fill_done = dbuf_fill_done
/* ARGSUSED */
void
dbuf_fill_done(dmu_buf_impl_t *db, dmu_tx_t *tx)
{
	mutex_enter(&db->db_mtx);
	DBUF_VERIFY(db);
	if (db->db_state & DB_FILL) {
		dbuf_dirty_record_t *dr;

		dr = list_head(&db->db_dirty_records);
		ASSERT(dr->dr_txg == tx->tx_txg);
		ASSERT(dr != db->db_data_pending);

		if (db->db_freed_in_flight) {
			ASSERT(db->db_level == 0);
			ASSERT(db->db_blkid != DMU_BONUS_BLKID);
			/* we were freed while filling */
			/* XXX dbuf_undirty? */
			bzero(db->db.db_data, db->db.db_size);
			db->db_freed_in_flight = FALSE;
			dbuf_dirty_record_cleanup_ranges(dr);
			DBUF_STATE_CHANGE(db, =, DB_CACHED,
			    "fill done handling freed in flight");
			dbuf_process_buf_sets(db, /*err*/0);
			dbuf_dispatch_override_zio(dr);
		} else {
			/*
			 * This function can be called with another state bit
			 * set, but if FILL is the only bit set, then the
			 * buffer has been fully filled.  Otherwise, clear the
			 * FILL bit, so it goes back to the steady state.
			 */
			if (db->db_state == DB_FILL) {
				DBUF_STATE_CHANGE(db, =, DB_CACHED,
				    "filler finished, complete buffer");
				dbuf_process_buf_sets(db, /*err*/0);
				dbuf_dispatch_override_zio(dr);
			} else {
				DBUF_STATE_CHANGE(db, &=, ~DB_FILL,
				    "filler finished, incomplete buffer");
				ASSERT(db->db_state & (DB_PARTIAL|DB_READ));
			}
		}
		cv_broadcast(&db->db_changed);
	}
	mutex_exit(&db->db_mtx);
}

/*
 * Directly assign a provided arc buf to a given dbuf if it's not referenced
 * by anybody except our caller. Otherwise copy arcbuf's contents to dbuf.
 */
void
dbuf_assign_arcbuf(dmu_buf_impl_t *db, arc_buf_t *buf, dmu_tx_t *tx)
{
	dbuf_dirty_record_t *dr;

	ASSERT(!refcount_is_zero(&db->db_holds));
	ASSERT(db->db_blkid != DMU_BONUS_BLKID);
	ASSERT(db->db_level == 0);
	ASSERT(DBUF_GET_BUFC_TYPE(db) == ARC_BUFC_DATA);
	ASSERT(buf != NULL);
	ASSERT(arc_buf_size(buf) == db->db.db_size);
	ASSERT(tx->tx_txg != 0);

	arc_return_buf(buf, db);
	ASSERT(arc_released(buf));
	(void) dbuf_dirty_with_arcbuf(db, tx, buf);
	dbuf_fill_done(db, tx);
}

/*
 * "Clear" the contents of this dbuf.  This will mark the dbuf
 * EVICTING and clear *most* of its references.  Unfortunately,
 * when we are not holding the dn_dbufs_mtx, we can't clear the
 * entry in the dn_dbufs list.  We have to wait until dbuf_destroy()
 * in this case.
 *
 * For callers from the DMU we will usually see:
 *	dbuf_clear()->arc_buf_evict()->dbuf_do_evict()->dbuf_destroy()
 *
 * For the arc callback, we will usually see:
 *	dbuf_do_evict()->dbuf_clear();dbuf_destroy()
 *
 * Sometimes, though, we will get a mix of these two:
 *	DMU: dbuf_clear()->arc_buf_evict()
 *	ARC: dbuf_do_evict()->dbuf_destroy()
 */
void
dbuf_clear(dmu_buf_impl_t *db, list_t *evict_list_p)
{
	dnode_t *dn;
	dmu_buf_impl_t *parent = db->db_parent;
	dmu_buf_impl_t *dndb;
	int dbuf_gone = FALSE;

	ASSERT(MUTEX_HELD(&db->db_mtx));
	ASSERT(refcount_is_zero(&db->db_holds));
	ASSERT(list_is_empty(&db->db_dirty_records));

	dbuf_evict_user(db, evict_list_p);

	if (db->db_state == DB_CACHED) {
		ASSERT(db->db.db_data != NULL);
		if (db->db_blkid == DMU_BONUS_BLKID) {
			zio_buf_free(db->db.db_data, DN_MAX_BONUSLEN);
			arc_space_return(DN_MAX_BONUSLEN, ARC_SPACE_OTHER);
		}
		db->db.db_data = NULL;
		DBUF_STATE_CHANGE(db, =, DB_UNCACHED, "buffer cleared");
	}

	ASSERT(db->db_state == DB_UNCACHED || db->db_state == DB_NOFILL);
	ASSERT(db->db_data_pending == NULL);
	ASSERT(list_is_empty(&db->db_dirty_records));

	DBUF_STATE_CHANGE(db, =, DB_EVICTING, "buffer eviction started");
	db->db_blkptr = NULL;

	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);
	dndb = dn->dn_dbuf;
	if (db->db_blkid != DMU_BONUS_BLKID && MUTEX_HELD(&dn->dn_dbufs_mtx)) {
		list_remove(&dn->dn_dbufs, db);
		(void) atomic_dec_32_nv(&dn->dn_dbufs_count);
		membar_producer();
		DB_DNODE_EXIT(db);
		/*
		 * Decrementing the dbuf count means that the hold corresponding
		 * to the removed dbuf is no longer discounted in dnode_move(),
		 * so the dnode cannot be moved until after we release the hold.
		 * The membar_producer() ensures visibility of the decremented
		 * value in dnode_move(), since DB_DNODE_EXIT doesn't actually
		 * release any lock.
		 */
		dnode_rele(dn, db);
		db->db_dnode_handle = NULL;
	} else {
		DB_DNODE_EXIT(db);
	}

	if (db->db_buf)
		dbuf_gone = arc_buf_evict(db->db_buf);

	if (!dbuf_gone)
		mutex_exit(&db->db_mtx);

	/*
	 * If this dbuf is referenced from an indirect dbuf,
	 * decrement the ref count on the indirect dbuf.
	 */
	if (parent && parent != dndb)
		dbuf_rele(parent, db);
}

static int
dbuf_findbp(dnode_t *dn, int level, uint64_t blkid, int fail_sparse,
    dmu_buf_impl_t **parentp, blkptr_t **bpp)
{
	int nlevels, epbs;

	*parentp = NULL;
	*bpp = NULL;

	ASSERT(blkid != DMU_BONUS_BLKID);

	if (blkid == DMU_SPILL_BLKID) {
		mutex_enter(&dn->dn_mtx);
		if (dn->dn_have_spill &&
		    (dn->dn_phys->dn_flags & DNODE_FLAG_SPILL_BLKPTR))
			*bpp = &dn->dn_phys->dn_spill;
		else
			*bpp = NULL;
		dbuf_add_ref(dn->dn_dbuf, NULL);
		*parentp = dn->dn_dbuf;
		mutex_exit(&dn->dn_mtx);
		return (0);
	}

	if (dn->dn_phys->dn_nlevels == 0)
		nlevels = 1;
	else
		nlevels = dn->dn_phys->dn_nlevels;

	epbs = dn->dn_indblkshift - SPA_BLKPTRSHIFT;

	ASSERT3U(level * epbs, <, 64);
	ASSERT(RW_LOCK_HELD(&dn->dn_struct_rwlock));
	if (level >= nlevels ||
	    (blkid > (dn->dn_phys->dn_maxblkid >> (level * epbs)))) {
		/* the buffer has no parent yet */
		return (SET_ERROR(ENOENT));
	} else if (level < nlevels-1) {
		/* this block is referenced from an indirect block */
		int err = dbuf_hold_impl(dn, level+1,
		    blkid >> epbs, fail_sparse, NULL, parentp, NULL);
		if (err)
			return (err);
		err = dbuf_read(*parentp, NULL,
		    (DB_RF_HAVESTRUCT | DB_RF_NOPREFETCH | DB_RF_CANFAIL));
		if (err) {
			dbuf_rele(*parentp, NULL);
			*parentp = NULL;
			return (err);
		}
		*bpp = ((blkptr_t *)(*parentp)->db.db_data) +
		    (blkid & ((1ULL << epbs) - 1));
		return (0);
	} else {
		/* the block is referenced from the dnode */
		ASSERT3U(level, ==, nlevels-1);
		ASSERT(dn->dn_phys->dn_nblkptr == 0 ||
		    blkid < dn->dn_phys->dn_nblkptr);
		if (dn->dn_dbuf) {
			dbuf_add_ref(dn->dn_dbuf, NULL);
			*parentp = dn->dn_dbuf;
		}
		*bpp = &dn->dn_phys->dn_blkptr[blkid];
		return (0);
	}
}

static dmu_buf_impl_t *
dbuf_create(dnode_t *dn, uint8_t level, uint64_t blkid,
    dmu_buf_impl_t *parent, blkptr_t *blkptr)
{
	objset_t *os = dn->dn_objset;
	dmu_buf_impl_t *db, *odb;

	ASSERT(RW_LOCK_HELD(&dn->dn_struct_rwlock));
	ASSERT(dn->dn_type != DMU_OT_NONE);

	db = kmem_cache_alloc(dbuf_cache, KM_SLEEP);

	list_create(&db->db_dirty_records, sizeof(dbuf_dirty_record_t),
	    offsetof(dbuf_dirty_record_t, db_dirty_record_link));

	list_create(&db->db_dmu_buf_sets, sizeof(dmu_context_node_t),
	    offsetof(dmu_context_node_t, dcn_link));

	db->db_objset = os;
	db->db.db_object = dn->dn_object;
	db->db_level = level;
	db->db_blkid = blkid;
	db->db_dirtycnt = 0;
	db->db_dnode_handle = dn->dn_handle;
	db->db_parent = parent;
	db->db_blkptr = blkptr;

	db->db_user = NULL;
	db->db_immediate_evict = 0;
	db->db_freed_in_flight = 0;

	if (blkid == DMU_BONUS_BLKID) {
		ASSERT3P(parent, ==, dn->dn_dbuf);
		db->db.db_size = DN_MAX_BONUSLEN -
		    (dn->dn_nblkptr-1) * sizeof (blkptr_t);
		ASSERT3U(db->db.db_size, >=, dn->dn_bonuslen);
		db->db.db_offset = DMU_BONUS_BLKID;
		DBUF_STATE_CHANGE(db, =, DB_UNCACHED, "bonus buffer created");
		/* the bonus dbuf is not placed in the hash table */
		arc_space_consume(sizeof (dmu_buf_impl_t), ARC_SPACE_OTHER);
		return (db);
	} else if (blkid == DMU_SPILL_BLKID) {
		db->db.db_size = (blkptr != NULL) ?
		    BP_GET_LSIZE(blkptr) : SPA_MINBLOCKSIZE;
		db->db.db_offset = 0;
	} else {
		int blocksize =
		    db->db_level ? 1<<dn->dn_indblkshift :  dn->dn_datablksz;
		db->db.db_size = blocksize;
		db->db.db_offset = db->db_blkid * blocksize;
	}

	/*
	 * Hold the dn_dbufs_mtx while we get the new dbuf
	 * in the hash table *and* added to the dbufs list.
	 * This prevents a possible deadlock with someone
	 * trying to look up this dbuf before its added to the
	 * dn_dbufs list.
	 */
	mutex_enter(&dn->dn_dbufs_mtx);
	db->db_state = DB_EVICTING; /* not worth logging this state change */
	if ((odb = dbuf_hash_insert(db)) != NULL) {
		/* someone else inserted it first */
		kmem_cache_free(dbuf_cache, db);
		mutex_exit(&dn->dn_dbufs_mtx);
		return (odb);
	}
	list_insert_head(&dn->dn_dbufs, db);
	DBUF_STATE_CHANGE(db, =, DB_UNCACHED, "regular buffer created");
	mutex_exit(&dn->dn_dbufs_mtx);
	arc_space_consume(sizeof (dmu_buf_impl_t), ARC_SPACE_OTHER);

	if (parent && parent != dn->dn_dbuf)
		dbuf_add_ref(parent, db);

	ASSERT(dn->dn_object == DMU_META_DNODE_OBJECT ||
	    refcount_count(&dn->dn_holds) > 0);
	(void) refcount_add(&dn->dn_holds, db);
	(void) atomic_inc_32_nv(&dn->dn_dbufs_count);

	dprintf_dbuf(db, "db=%p\n", db);

	return (db);
}

static int
dbuf_do_evict(void *private)
{
	arc_buf_t *buf = private;
	dmu_buf_impl_t *db = buf->b_private;
	list_t evict_list;

	dmu_buf_create_user_evict_list(&evict_list);

	if (!MUTEX_HELD(&db->db_mtx))
		mutex_enter(&db->db_mtx);

	ASSERT(refcount_is_zero(&db->db_holds));
	ASSERT(list_is_empty(&db->db_dirty_records));

	if (db->db_state != DB_EVICTING) {
		ASSERT(db->db_state == DB_CACHED);
		DBUF_VERIFY(db);
		db->db_buf = NULL;
		dbuf_evict(db, &evict_list);
	} else {
		mutex_exit(&db->db_mtx);
		dbuf_destroy(db);
	}
	dmu_buf_destroy_user_evict_list(&evict_list);
	return (0);
}

static void
dbuf_destroy(dmu_buf_impl_t *db)
{
	ASSERT(refcount_is_zero(&db->db_holds));

	if (db->db_blkid != DMU_BONUS_BLKID) {
		/*
		 * If this dbuf is still on the dn_dbufs list,
		 * remove it from that list.
		 */
		if (db->db_dnode_handle != NULL) {
			dnode_t *dn;

			DB_DNODE_ENTER(db);
			dn = DB_DNODE(db);
			mutex_enter(&dn->dn_dbufs_mtx);
			list_remove(&dn->dn_dbufs, db);
			(void) atomic_dec_32_nv(&dn->dn_dbufs_count);
			mutex_exit(&dn->dn_dbufs_mtx);
			DB_DNODE_EXIT(db);
			/*
			 * Decrementing the dbuf count means that the hold
			 * corresponding to the removed dbuf is no longer
			 * discounted in dnode_move(), so the dnode cannot be
			 * moved until after we release the hold.
			 */
			dnode_rele(dn, db);
			db->db_dnode_handle = NULL;
		}
		dbuf_hash_remove(db);
	}
	db->db_parent = NULL;
	db->db_buf = NULL;
	list_destroy(&db->db_dirty_records);
	list_destroy(&db->db_dmu_buf_sets);

	ASSERT(!list_link_active(&db->db_link));
	ASSERT(db->db.db_data == NULL);
	ASSERT(db->db_hash_next == NULL);
	ASSERT(db->db_blkptr == NULL);
	ASSERT(db->db_data_pending == NULL);

	kmem_cache_free(dbuf_cache, db);
	arc_space_return(sizeof (dmu_buf_impl_t), ARC_SPACE_OTHER);
}

void
dbuf_prefetch(dnode_t *dn, uint64_t blkid)
{
	dmu_buf_impl_t *db = NULL;
	blkptr_t *bp = NULL;

	ASSERT(blkid != DMU_BONUS_BLKID);
	ASSERT(RW_LOCK_HELD(&dn->dn_struct_rwlock));

	if (dnode_block_freed(dn, blkid))
		return;

	/* dbuf_find() returns with db_mtx held */
	if (db = dbuf_find(dn, 0, blkid)) {
		/*
		 * This dbuf is already in the cache.  We assume that
		 * it is already CACHED, or else about to be either
		 * read or filled.
		 */
		mutex_exit(&db->db_mtx);
		return;
	}

	if (dbuf_findbp(dn, 0, blkid, TRUE, &db, &bp) == 0) {
		if (bp && !BP_IS_HOLE(bp)) {
			int priority = dn->dn_type == DMU_OT_DDT_ZAP ?
			    ZIO_PRIORITY_DDT_PREFETCH : ZIO_PRIORITY_ASYNC_READ;
			dsl_dataset_t *ds = dn->dn_objset->os_dsl_dataset;
			uint32_t aflags = ARC_NOWAIT | ARC_PREFETCH;
			zbookmark_t zb;

			SET_BOOKMARK(&zb, ds ? ds->ds_object : DMU_META_OBJSET,
			    dn->dn_object, 0, blkid);

			(void) arc_read(NULL, dn->dn_objset->os_spa,
			    bp, NULL, NULL, priority,
			    ZIO_FLAG_CANFAIL | ZIO_FLAG_SPECULATIVE,
			    &aflags, &zb);
		}
		if (db)
			dbuf_rele(db, NULL);
	}
}

/*
 * Returns with db_holds incremented, and db_mtx not held.
 * Note: dn_struct_rwlock must be held.
 *
 * If buf_set is not NULL, the dbuf must notify the buffer set once a read
 * is completed.
 */
int
dbuf_hold_impl(dnode_t *dn, uint8_t level, uint64_t blkid, int fail_sparse,
    void *tag, dmu_buf_impl_t **dbp, dmu_buf_set_t *buf_set)
{
	dmu_buf_impl_t *db, *parent = NULL;
	list_t evict_list;

	ASSERT(blkid != DMU_BONUS_BLKID);
	ASSERT(RW_LOCK_HELD(&dn->dn_struct_rwlock));
	ASSERT3U(dn->dn_nlevels, >, level);

	dmu_buf_create_user_evict_list(&evict_list);

	*dbp = NULL;
top:
	/* dbuf_find() returns with db_mtx held */
	db = dbuf_find(dn, level, blkid);

	if (db == NULL) {
		blkptr_t *bp = NULL;
		int err;

		ASSERT3P(parent, ==, NULL);
		err = dbuf_findbp(dn, level, blkid, fail_sparse, &parent, &bp);
		if (fail_sparse) {
			if (err == 0 && bp && BP_IS_HOLE(bp))
				err = SET_ERROR(ENOENT);
			if (err) {
				if (parent)
					dbuf_rele(parent, NULL);
				return (err);
			}
		}
		if (err && err != ENOENT)
			return (err);
		db = dbuf_create(dn, level, blkid, parent, bp);
	}

	if (db->db_buf && refcount_is_zero(&db->db_holds)) {
		arc_buf_add_ref(db->db_buf, db);
		if (db->db_buf->b_data == NULL) {
			dbuf_clear(db, &evict_list);
			if (parent) {
				dbuf_rele(parent, NULL);
				parent = NULL;
			}
			goto top;
		}
		ASSERT3P(db->db.db_data, ==, db->db_buf->b_data);
	}

	ASSERT(db->db_buf == NULL || arc_referenced(db->db_buf));

	/*
	 * If this buffer is currently syncing out, and we are are
	 * still referencing it from db_data, we need to make a copy
	 * of it in case we decide we want to dirty it again in this txg.
	 */
	if (db->db_data_pending && db->db_level == 0 &&
	    dn->dn_object != DMU_META_DNODE_OBJECT &&
	    db->db_state == DB_CACHED) {
		dbuf_dirty_record_t *dr = db->db_data_pending;

		/* dbuf_sync_bonus does not set db_data_pending. */
		ASSERT(db->db_blkid != DMU_BONUS_BLKID);

		if (dr->dt.dl.dr_data == db->db_buf) {
			dbuf_set_data(db, dbuf_alloc_arcbuf(db));
			bcopy(dr->dt.dl.dr_data->b_data, db->db.db_data,
			    db->db.db_size);
		}
	}

	(void) refcount_add(&db->db_holds, tag);
	DBUF_VERIFY(db);
	/* If a reading buffer set is associated, add the callback now. */
	if (buf_set != NULL && (buf_set->dmu_ctx->flags & DMU_CTX_FLAG_READ)) {
		if (db->db_state == DB_CACHED) {
			/* Dbuf is already at the desired state. */
			dmu_buf_set_rele(buf_set, /*err*/0);
		} else
			dmu_context_node_add(&db->db_dmu_buf_sets, buf_set);
	}
	mutex_exit(&db->db_mtx);

	dmu_buf_destroy_user_evict_list(&evict_list);

	/* NOTE: we can't rele the parent until after we drop the db_mtx */
	if (parent)
		dbuf_rele(parent, NULL);

	ASSERT3P(DB_DNODE(db), ==, dn);
	ASSERT3U(db->db_blkid, ==, blkid);
	ASSERT3U(db->db_level, ==, level);
	*dbp = db;

	return (0);
}

dmu_buf_impl_t *
dbuf_hold(dnode_t *dn, uint64_t blkid, void *tag)
{
	return (dbuf_hold_level(dn, 0, blkid, tag));
}

dmu_buf_impl_t *
dbuf_hold_level(dnode_t *dn, int level, uint64_t blkid, void *tag)
{
	dmu_buf_impl_t *db;
	int err = dbuf_hold_impl(dn, level, blkid, FALSE, tag, &db,
	    /*buf_set*/NULL);
	return (err ? NULL : db);
}

void
dbuf_create_bonus(dnode_t *dn)
{
	ASSERT(RW_WRITE_HELD(&dn->dn_struct_rwlock));

	ASSERT(dn->dn_bonus == NULL);
	dn->dn_bonus = dbuf_create(dn, 0, DMU_BONUS_BLKID, dn->dn_dbuf, NULL);
}

int
dbuf_spill_set_blksz(dmu_buf_t *db_fake, uint64_t blksz, dmu_tx_t *tx)
{
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)db_fake;
	dnode_t *dn;

	if (db->db_blkid != DMU_SPILL_BLKID)
		return (SET_ERROR(ENOTSUP));
	if (blksz == 0)
		blksz = SPA_MINBLOCKSIZE;
	if (blksz > SPA_MAXBLOCKSIZE)
		blksz = SPA_MAXBLOCKSIZE;
	else
		blksz = P2ROUNDUP(blksz, SPA_MINBLOCKSIZE);

	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);
	rw_enter(&dn->dn_struct_rwlock, RW_WRITER);
	dbuf_new_size(db, blksz, tx);
	rw_exit(&dn->dn_struct_rwlock);
	DB_DNODE_EXIT(db);

	return (0);
}

void
dbuf_rm_spill(dnode_t *dn, dmu_tx_t *tx)
{
	dbuf_free_range(dn, DMU_SPILL_BLKID, DMU_SPILL_BLKID, tx);
}

#pragma weak dmu_buf_add_ref = dbuf_add_ref
void
dbuf_add_ref(dmu_buf_impl_t *db, void *tag)
{
	int64_t holds = refcount_add(&db->db_holds, tag);
	ASSERT(holds > 1);
}

/*
 * If you call dbuf_rele() you had better not be referencing the dnode handle
 * unless you have some other direct or indirect hold on the dnode. (An indirect
 * hold is a hold on one of the dnode's dbufs, including the bonus buffer.)
 * Without that, the dbuf_rele() could lead to a dnode_rele() followed by the
 * dnode's parent dbuf evicting its dnode handles.
 */
#pragma weak dmu_buf_rele = dbuf_rele
void
dbuf_rele(dmu_buf_impl_t *db, void *tag)
{
	mutex_enter(&db->db_mtx);
	dbuf_rele_and_unlock(db, tag);
}

/*
 * dbuf_rele() for an already-locked dbuf.  This is necessary to allow
 * db_dirtycnt and db_holds to be updated atomically.
 */
void
dbuf_rele_and_unlock(dmu_buf_impl_t *db, void *tag)
{
	int64_t holds;
	list_t evict_list;

	ASSERT(MUTEX_HELD(&db->db_mtx));
	DBUF_VERIFY(db);

	dmu_buf_create_user_evict_list(&evict_list);

	/*
	 * Remove the reference to the dbuf before removing its hold on the
	 * dnode so we can guarantee in dnode_move() that a referenced bonus
	 * buffer has a corresponding dnode hold.
	 */
	holds = refcount_remove(&db->db_holds, tag);
	ASSERT(holds >= 0);

	/*
	 * We can't freeze indirects if there is a possibility that they
	 * may be modified in the current syncing context, or if there could
	 * be data in flight.
	 */
	if (db->db_buf && db->db_state == DB_CACHED &&
	    holds == (db->db_level == 0 ? db->db_dirtycnt : 0))
		arc_buf_freeze(db->db_buf);

	if (holds == db->db_dirtycnt &&
	    db->db_level == 0 && db->db_immediate_evict)
		dbuf_evict_user(db, &evict_list);

	if (holds == 0) {
		if (db->db_blkid == DMU_BONUS_BLKID) {
			mutex_exit(&db->db_mtx);

			/*
			 * If the dnode moves here, we cannot cross this barrier
			 * until the move completes.
			 */
			DB_DNODE_ENTER(db);
			(void) atomic_dec_32_nv(&DB_DNODE(db)->dn_dbufs_count);
			membar_producer();
			DB_DNODE_EXIT(db);
			/*
			 * The bonus buffer's dnode hold is no longer discounted
			 * in dnode_move(). The dnode cannot move until after
			 * the dnode_rele().
			 */
			dnode_rele(DB_DNODE(db), db);
		} else if (db->db_buf == NULL) {
			/*
			 * This is a special case: we never associated this
			 * dbuf with any data allocated from the ARC.
			 */
#ifdef ZFS_DEBUG
			if ((db->db_state & (DB_UNCACHED|DB_NOFILL)) == 0) {
				__dprintf(__FILE__, __func__, __LINE__,
				    "%s: dbuf invalid without ARC buffer: "
				    "state %d lvl=%d blkid=%d obj=%d\n",
				    __func__, db->db_state, db->db_level,
				    db->db_blkid, db->db.db_object);
			}
#endif
			ASSERT(db->db_state == DB_UNCACHED ||
			    db->db_state == DB_NOFILL);
			dbuf_evict(db, &evict_list);
		} else if (arc_released(db->db_buf)) {
			arc_buf_t *buf = db->db_buf;
			/*
			 * This dbuf has anonymous data associated with it.
			 */
			dbuf_clear_data(db, &evict_list);
			VERIFY(arc_buf_remove_ref(buf, db));
			dbuf_evict(db, &evict_list);
		} else {
			VERIFY(!arc_buf_remove_ref(db->db_buf, db));

			/*
			 * A dbuf will be eligible for eviction if either the
			 * 'primarycache' property is set or a duplicate
			 * copy of this buffer is already cached in the arc.
			 *
			 * In the case of the 'primarycache' a buffer
			 * is considered for eviction if it matches the
			 * criteria set in the property.
			 *
			 * To decide if our buffer is considered a
			 * duplicate, we must call into the arc to determine
			 * if multiple buffers are referencing the same
			 * block on-disk. If so, then we simply evict
			 * ourselves.
			 */
			if (!DBUF_IS_CACHEABLE(db) ||
			    arc_buf_eviction_needed(db->db_buf))
				dbuf_clear(db, &evict_list);
			else
				mutex_exit(&db->db_mtx);
		}
	} else {
		mutex_exit(&db->db_mtx);
	}
	dmu_buf_destroy_user_evict_list(&evict_list);
}

#pragma weak dmu_buf_refcount = dbuf_refcount
uint64_t
dbuf_refcount(dmu_buf_impl_t *db)
{
	return (refcount_count(&db->db_holds));
}

boolean_t
dmu_buf_freeable(dmu_buf_t *dbuf)
{
	boolean_t res = B_FALSE;
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)dbuf;

	if (db->db_blkptr)
		res = dsl_dataset_block_freeable(db->db_objset->os_dsl_dataset,
		    db->db_blkptr, db->db_blkptr->blk_birth);

	return (res);
}

blkptr_t *
dmu_buf_get_blkptr(dmu_buf_t *db)
{
	dmu_buf_impl_t *dbi = (dmu_buf_impl_t *)db;
	return (dbi->db_blkptr);
}

static void
dbuf_check_blkptr(dnode_t *dn, dmu_buf_impl_t *db)
{
	/* ASSERT(dmu_tx_is_syncing(tx) */
	ASSERT(MUTEX_HELD(&db->db_mtx));

	if (db->db_blkptr != NULL)
		return;

	if (db->db_blkid == DMU_SPILL_BLKID) {
		db->db_blkptr = &dn->dn_phys->dn_spill;
		BP_ZERO(db->db_blkptr);
		return;
	}
	if (db->db_level == dn->dn_phys->dn_nlevels-1) {
		/*
		 * This buffer was allocated at a time when there was
		 * no available blkptrs from the dnode, or it was
		 * inappropriate to hook it in (i.e., nlevels mis-match).
		 */
		ASSERT(db->db_blkid < dn->dn_phys->dn_nblkptr);
		ASSERT(db->db_parent == NULL);
		db->db_parent = dn->dn_dbuf;
		db->db_blkptr = &dn->dn_phys->dn_blkptr[db->db_blkid];
		DBUF_VERIFY(db);
	} else {
		dmu_buf_impl_t *parent = db->db_parent;
		int epbs = dn->dn_phys->dn_indblkshift - SPA_BLKPTRSHIFT;

		ASSERT(dn->dn_phys->dn_nlevels > 1);
		if (parent == NULL) {
			mutex_exit(&db->db_mtx);
			rw_enter(&dn->dn_struct_rwlock, RW_READER);
			parent = dbuf_hold_level(dn, db->db_level + 1,
			    db->db_blkid >> epbs, db);
			rw_exit(&dn->dn_struct_rwlock);
			mutex_enter(&db->db_mtx);
			db->db_parent = parent;
		}
		db->db_blkptr = (blkptr_t *)parent->db.db_data +
		    (db->db_blkid & ((1ULL << epbs) - 1));
		DBUF_VERIFY(db);
	}
}

boolean_t
dbuf_resolve_still_pending(dbuf_dirty_record_t *dr, zio_t **dr_zio, zio_t *zio)
{
	/* Resolve race with dbuf_read_complete()/dbuf_free_range() */
	boolean_t resolve_pending;
	mutex_enter(&dr->dr_dbuf->db_mtx);
	resolve_pending = !list_is_empty(&dr->dt.dl.write_ranges);
	if (resolve_pending) {
		ASSERT(*dr_zio == NULL);
		*dr_zio = zio;
#ifdef ZFS_DEBUG
		if (dr_zio == &dr->dr_zio)
			DEBUG_COUNTER_INC(syncer_deferred_resolves);
		else if (dr_zio == &dr->dr_override_zio)
			DEBUG_COUNTER_INC(override_deferred_resolves);
		else
			ASSERT(!"unexpected zio_t **dr_zio!");
#endif
	}
	mutex_exit(&dr->dr_dbuf->db_mtx);
	return (resolve_pending);
}

static void
dbuf_sync_indirect(dbuf_dirty_record_t *dr, dmu_tx_t *tx)
{
	dmu_buf_impl_t *db = dr->dr_dbuf;
	dnode_t *dn;
	zio_t *zio;

	ASSERT(dmu_tx_is_syncing(tx));

	dprintf_dbuf_bp(db, db->db_blkptr, "blkptr=%p", db->db_blkptr);

	mutex_enter(&db->db_mtx);

	ASSERT(db->db_level > 0);
	DBUF_VERIFY(db);

	/* Read the block if it hasn't been read yet. */
	if (db->db_buf == NULL) {
		mutex_exit(&db->db_mtx);
		(void) dbuf_read(db, NULL, DB_RF_MUST_SUCCEED);
		mutex_enter(&db->db_mtx);
	}
	ASSERT3U(db->db_state, ==, DB_CACHED);
	ASSERT(db->db_buf != NULL);

	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);
	/* Indirect block size must match what the dnode thinks it is. */
	ASSERT3U(db->db.db_size, ==, 1<<dn->dn_phys->dn_indblkshift);
	dbuf_check_blkptr(dn, db);
	DB_DNODE_EXIT(db);

	/* Provide the pending dirty record to child dbufs */
	db->db_data_pending = dr;
	ASSERT(list_next(&db->db_dirty_records, dr) == NULL);

	mutex_exit(&db->db_mtx);
	zio = dr->dr_zio = dbuf_write(dr, db->db_buf, tx);
	mutex_enter(&dr->dt.di.dr_mtx);

	dbuf_sync_list(&dr->dt.di.dr_children, tx);
	ASSERT(list_head(&dr->dt.di.dr_children) == NULL);
	mutex_exit(&dr->dt.di.dr_mtx);
	zio_nowait(zio);
}

static void
dbuf_sync_bonus(dbuf_dirty_record_t *dr, dmu_tx_t *tx)
{
	dmu_buf_impl_t *db = dr->dr_dbuf;
	void *data = dr->dt.dl.dr_data;
	dnode_t *dn;

	ASSERT0(db->db_level);
	ASSERT(MUTEX_HELD(&db->db_mtx));
	ASSERT(DB_DNODE_HELD(db));
	ASSERT(db->db_blkid == DMU_BONUS_BLKID);
	ASSERT(data != NULL);

	dn = DB_DNODE(db);
	ASSERT3U(dn->dn_phys->dn_bonuslen, <=, DN_MAX_BONUSLEN);

	bcopy(data, DN_BONUS(dn->dn_phys), dn->dn_phys->dn_bonuslen);
	DB_DNODE_EXIT(db);

	dbuf_undirty_bonus(dr);
	dbuf_rele_and_unlock(db, (void *)(uintptr_t)tx->tx_txg);
}

static void
dbuf_sync_leaf(dbuf_dirty_record_t *dr, dmu_tx_t *tx)
{
	arc_buf_t **datap = &dr->dt.dl.dr_data;
	dmu_buf_impl_t *db = dr->dr_dbuf;
	dnode_t *dn;
	objset_t *os;
	zio_t *zio;
	uint64_t txg = tx->tx_txg;
	boolean_t resolve_pending;

	ASSERT(dmu_tx_is_syncing(tx));

	dprintf_dbuf_bp(db, db->db_blkptr, "blkptr=%p", db->db_blkptr);

	mutex_enter(&db->db_mtx);
	if (db->db_state & DB_PARTIAL) {
		/*
		 * Time has run out for waiting on any writer to fill
		 * this buffer.
		 */
		ASSERT(arc_released(*datap));
		dbuf_transition_to_read(db);
	}

	/*
	 * To be synced, we must be dirtied.  But we
	 * might have been freed after the dirty.
	 */
	if (db->db_state == DB_UNCACHED) {
		/* This buffer has been freed since it was dirtied */
		ASSERT(db->db.db_data == NULL);
	} else if (db->db_state & DB_FILL) {
		/*
		 * This buffer is being modified.  Those modifications
		 * should be in a newer transaction group and not
		 * reference the data we are about to write.
		 */
		ASSERT(db->db.db_data != dr->dt.dl.dr_data);
	} else {
		ASSERT(db->db_state & (DB_CACHED|DB_READ|DB_NOFILL));
	}
	DBUF_VERIFY(db);

	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);

	if (db->db_blkid == DMU_SPILL_BLKID) {
		mutex_enter(&dn->dn_mtx);
		dn->dn_phys->dn_flags |= DNODE_FLAG_SPILL_BLKPTR;
		mutex_exit(&dn->dn_mtx);
	}

	/*
	 * If this is a bonus buffer, simply copy the bonus data into the
	 * dnode.  It will be written out when the dnode is synced (and it
	 * will be synced, since it must have been dirty for dbuf_sync to
	 * be called).
	 */
	if (db->db_blkid == DMU_BONUS_BLKID) {
		dbuf_sync_bonus(dr, tx);
		return;
	}

	os = dn->dn_objset;

	/*
	 * This function may have dropped the db_mtx lock allowing a dmu_sync
	 * operation to sneak in. As a result, we need to ensure that we
	 * don't check the dr_override_state until we have returned from
	 * dbuf_check_blkptr.
	 */
	dbuf_check_blkptr(dn, db);

	/*
	 * If this buffer is in the middle of an immediate write,
	 * wait for the synchronous IO to complete.
	 */
	while (dr->dt.dl.dr_override_state == DR_IN_DMU_SYNC) {
		ASSERT(dn->dn_object != DMU_META_DNODE_OBJECT);
		cv_wait(&db->db_changed, &db->db_mtx);
		ASSERT(dr->dt.dl.dr_override_state != DR_NOT_OVERRIDDEN);
	}

	/* Remember if we need to defer write execution to dbuf_read_done(). */
	resolve_pending = !list_is_empty(&dr->dt.dl.write_ranges);

	/*
	 * Syncer splits must be deferred until the buffer contents
	 * are fully valid.
	 */
	if (resolve_pending == B_FALSE &&
	    dn->dn_object != DMU_META_DNODE_OBJECT)
		dbuf_syncer_split(db, dr, /*deferred_split*/B_FALSE);

	/* Notify the world that this dirty record is about to write. */
	db->db_data_pending = dr;
	ASSERT(list_next(&db->db_dirty_records, dr) == NULL);

	mutex_exit(&db->db_mtx);

	zio = dbuf_write(dr, *datap, tx);

	if (resolve_pending &&
	    dbuf_resolve_still_pending(dr, &dr->dr_zio, zio)) {
		DB_DNODE_EXIT(db);
		return;
	}

	dr->dr_zio = zio;
	ASSERT(!list_link_active(&dr->dr_dirty_node));
	if (dn->dn_object == DMU_META_DNODE_OBJECT) {
		list_insert_tail(&dn->dn_dirty_records[txg&TXG_MASK], dr);
		DB_DNODE_EXIT(db);
	} else {
		/*
		 * Although zio_nowait() does not "wait for an IO", it does
		 * initiate the IO. If this is an empty write it seems plausible
		 * that the IO could actually be completed before the nowait
		 * returns. We need to DB_DNODE_EXIT() first in case
		 * zio_nowait() invalidates the dbuf.
		 */
		DB_DNODE_EXIT(db);
		zio_nowait(dr->dr_zio);
	}
}

void
dbuf_sync_list(list_t *list, dmu_tx_t *tx)
{
	dbuf_dirty_record_t *dr;

	while (dr = list_head(list)) {
		if (dr->dr_zio != NULL) {
			/*
			 * If we find an already initialized zio then we
			 * are processing the meta-dnode, and we have finished.
			 * The dbufs for all dnodes are put back on the list
			 * during processing, so that we can zio_wait()
			 * these IOs after initiating all child IOs.
			 */
			ASSERT3U(dr->dr_dbuf->db.db_object, ==,
			    DMU_META_DNODE_OBJECT);
			break;
		}
		list_remove(list, dr);
		if (dr->dr_dbuf->db_level > 0)
			dbuf_sync_indirect(dr, tx);
		else
			dbuf_sync_leaf(dr, tx);
	}
}

/* ARGSUSED */
static void
dbuf_write_ready(zio_t *zio, arc_buf_t *buf, void *vdb)
{
	dmu_buf_impl_t *db = vdb;
	dnode_t *dn;
	blkptr_t *bp = zio->io_bp;
	blkptr_t *bp_orig = &zio->io_bp_orig;
	spa_t *spa = zio->io_spa;
	int64_t delta;
	uint64_t fill = 0;
	int i;

	ASSERT(db->db_blkptr == bp);

	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);
	delta = bp_get_dsize_sync(spa, bp) - bp_get_dsize_sync(spa, bp_orig);
	dnode_diduse_space(dn, delta - zio->io_prev_space_delta);
	zio->io_prev_space_delta = delta;

	if (BP_IS_HOLE(bp)) {
		ASSERT(bp->blk_fill == 0);
		DB_DNODE_EXIT(db);
		return;
	}

	ASSERT((db->db_blkid != DMU_SPILL_BLKID &&
	    BP_GET_TYPE(bp) == dn->dn_type) ||
	    (db->db_blkid == DMU_SPILL_BLKID &&
	    BP_GET_TYPE(bp) == dn->dn_bonustype));
	ASSERT(BP_GET_LEVEL(bp) == db->db_level);

	mutex_enter(&db->db_mtx);

#ifdef ZFS_DEBUG
	if (db->db_blkid == DMU_SPILL_BLKID) {
		ASSERT(dn->dn_phys->dn_flags & DNODE_FLAG_SPILL_BLKPTR);
		ASSERT(!(BP_IS_HOLE(db->db_blkptr)) &&
		    db->db_blkptr == &dn->dn_phys->dn_spill);
	}
#endif

	if (db->db_level == 0) {
		mutex_enter(&dn->dn_mtx);
		if (db->db_blkid > dn->dn_phys->dn_maxblkid &&
		    db->db_blkid != DMU_SPILL_BLKID)
			dn->dn_phys->dn_maxblkid = db->db_blkid;
		mutex_exit(&dn->dn_mtx);

		if (dn->dn_type == DMU_OT_DNODE) {
			dnode_phys_t *dnp = db->db.db_data;
			for (i = db->db.db_size >> DNODE_SHIFT; i > 0;
			    i--, dnp++) {
				if (dnp->dn_type != DMU_OT_NONE)
					fill++;
			}
		} else {
			fill = 1;
		}
	} else {
		blkptr_t *ibp = db->db.db_data;
		ASSERT3U(db->db.db_size, ==, 1<<dn->dn_phys->dn_indblkshift);
		for (i = db->db.db_size >> SPA_BLKPTRSHIFT; i > 0; i--, ibp++) {
			if (BP_IS_HOLE(ibp))
				continue;
			fill += ibp->blk_fill;
		}
	}
	DB_DNODE_EXIT(db);

	bp->blk_fill = fill;

	mutex_exit(&db->db_mtx);
}

/* ARGSUSED */
static void
dbuf_write_done(zio_t *zio, arc_buf_t *buf, void *vdb)
{
	dmu_buf_impl_t *db = vdb;
	blkptr_t *bp = zio->io_bp;
	blkptr_t *bp_orig = &zio->io_bp_orig;
	uint64_t txg = zio->io_txg;
	dbuf_dirty_record_t *dr;

	ASSERT0(zio->io_error);
	ASSERT(db->db_blkptr == bp);

	/*
	 * For nopwrites and rewrites we ensure that the bp matches our
	 * original and bypass all the accounting.
	 */
	if (zio->io_flags & (ZIO_FLAG_IO_REWRITE | ZIO_FLAG_NOPWRITE)) {
		ASSERT(BP_EQUAL(bp, bp_orig));
	} else {
		objset_t *os;
		dsl_dataset_t *ds;
		dmu_tx_t *tx;

		DB_GET_OBJSET(&os, db);
		ds = os->os_dsl_dataset;
		tx = os->os_synctx;

		(void) dsl_dataset_block_kill(ds, bp_orig, tx, B_TRUE);
		dsl_dataset_block_born(ds, bp, tx);
	}

	mutex_enter(&db->db_mtx);

	DBUF_VERIFY(db);

	/*
	 * Now that the write is completed, the dirty record it resolves is
	 * no longer needed, so remove it.
	 */
	ASSERT(db->db_data_pending->dr_dbuf == db);
	dbuf_undirty_write(db->db_data_pending, txg);
	dbuf_rele_and_unlock(db, (void *)(uintptr_t)txg);
}

static void
dbuf_write_nofill_ready(zio_t *zio)
{
	dbuf_write_ready(zio, NULL, zio->io_private);
}

static void
dbuf_write_nofill_done(zio_t *zio)
{
	dbuf_write_done(zio, NULL, zio->io_private);
}

static void
dbuf_write_override_ready(zio_t *zio, arc_buf_t *buf, void *dr_private)
{
	dbuf_dirty_record_t *dr = dr_private;
	dmu_buf_impl_t *db = dr->dr_dbuf;

	dbuf_write_ready(zio, NULL, db);
}

static void
dbuf_write_override_done(zio_t *zio, arc_buf_t *buf, void *dr_private)
{
	dbuf_dirty_record_t *dr = dr_private;
	dmu_buf_impl_t *db = dr->dr_dbuf;
	blkptr_t *obp = &dr->dt.dl.dr_overridden_by;

	mutex_enter(&db->db_mtx);
	if (!BP_EQUAL(zio->io_bp, obp)) {
		if (!BP_IS_HOLE(obp))
			dsl_free(spa_get_dsl(zio->io_spa), zio->io_txg, obp);
		arc_release(dr->dt.dl.dr_data, db);
	}
	mutex_exit(&db->db_mtx);

	dbuf_write_done(zio, NULL, db);
}

/* Issue I/O to commit a dirty buffer to disk. */
static zio_t *
dbuf_write(dbuf_dirty_record_t *dr, arc_buf_t *data, dmu_tx_t *tx)
{
	dmu_buf_impl_t *db = dr->dr_dbuf;
	dnode_t *dn;
	objset_t *os;
	dmu_buf_impl_t *parent = db->db_parent;
	uint64_t txg = tx->tx_txg;
	zbookmark_t zb;
	zio_prop_t zp;
	zio_t *pio; /* parent I/O */
	zio_t *dr_zio;
	int wp_flag = 0;

	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);
	os = dn->dn_objset;

	if (db->db_state != DB_NOFILL) {
		if (db->db_level > 0 || dn->dn_type == DMU_OT_DNODE) {
			/*
			 * Private object buffers are released here rather
			 * than in dbuf_dirty() since they are only modified
			 * in the syncing context and we don't want the
			 * overhead of making multiple copies of the data.
			 */
			if (BP_IS_HOLE(db->db_blkptr)) {
				arc_buf_thaw(data);
			} else {
				dbuf_release_bp(db);
			}
		}
	}

	if (parent != dn->dn_dbuf) {
		/* Our parent is an indirect block. */
		/* We have a dirty parent that has been scheduled for write. */
		ASSERT(parent && parent->db_data_pending);
		/* Our parent's buffer is one level closer to the dnode. */
		ASSERT(db->db_level == parent->db_level-1);
		/*
		 * We're about to modify our parent's db_data by modifying
		 * our block pointer, so the parent must be released.
		 */
		ASSERT(arc_released(parent->db_buf));
		pio = parent->db_data_pending->dr_zio;
	} else {
		/* Our parent is the dnode itself. */
		ASSERT((db->db_level == dn->dn_phys->dn_nlevels-1 &&
		    db->db_blkid != DMU_SPILL_BLKID) ||
		    (db->db_blkid == DMU_SPILL_BLKID && db->db_level == 0));
		if (db->db_blkid != DMU_SPILL_BLKID)
			ASSERT3P(db->db_blkptr, ==,
			    &dn->dn_phys->dn_blkptr[db->db_blkid]);
		pio = dn->dn_zio;
	}

	ASSERT(db->db_level == 0 || data == db->db_buf);
	ASSERT3U(db->db_blkptr->blk_birth, <=, txg);
	ASSERT(pio);

	SET_BOOKMARK(&zb, os->os_dsl_dataset ?
	    os->os_dsl_dataset->ds_object : DMU_META_OBJSET,
	    db->db.db_object, db->db_level, db->db_blkid);

	if (db->db_blkid == DMU_SPILL_BLKID)
		wp_flag = WP_SPILL;
	wp_flag |= (db->db_state == DB_NOFILL) ? WP_NOFILL : 0;

	dmu_write_policy(os, dn, db->db_level, wp_flag, &zp);
	DB_DNODE_EXIT(db);

	if (db->db_level == 0 && dr->dt.dl.dr_override_state == DR_OVERRIDDEN) {
		/*
		 * An immediate write has occurred via dmu_sync, which means
		 * its block pointer override needs to be handled here.
		 */
		ASSERT(db->db_state != DB_NOFILL);
		ASSERT(arc_released(data));
		dr_zio = arc_write(pio, os->os_spa, txg,
		    db->db_blkptr, data, DBUF_IS_L2CACHEABLE(db),
		    DBUF_IS_L2COMPRESSIBLE(db), &zp, dbuf_write_override_ready,
		    dbuf_write_override_done, dr, ZIO_PRIORITY_ASYNC_WRITE,
		    ZIO_FLAG_MUSTSUCCEED, &zb);
		zio_write_override(dr_zio, &dr->dt.dl.dr_overridden_by,
		    dr->dt.dl.dr_copies, dr->dt.dl.dr_nopwrite);
	} else if (db->db_state == DB_NOFILL) {
		ASSERT(zp.zp_checksum == ZIO_CHECKSUM_OFF);
		dr_zio = zio_write(pio, os->os_spa, txg,
		    db->db_blkptr, NULL, db->db.db_size, &zp,
		    dbuf_write_nofill_ready, dbuf_write_nofill_done, db,
		    ZIO_PRIORITY_ASYNC_WRITE,
		    ZIO_FLAG_MUSTSUCCEED | ZIO_FLAG_NODATA, &zb);
	} else {
		ASSERT(arc_released(data));
		dr_zio = arc_write(pio, os->os_spa, txg,
		    db->db_blkptr, data, DBUF_IS_L2CACHEABLE(db),
		    DBUF_IS_L2COMPRESSIBLE(db), &zp, dbuf_write_ready,
		    dbuf_write_done, db, ZIO_PRIORITY_ASYNC_WRITE,
		    ZIO_FLAG_MUSTSUCCEED, &zb);
	}

	return (dr_zio);
}
