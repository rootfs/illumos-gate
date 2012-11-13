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
 */

#ifndef	_SYS_ZAP_LEAF_H
#define	_SYS_ZAP_LEAF_H

#include <sys/zap.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct zap;
struct zap_name;
struct zap_stats;

#define	ZAP_LEAF_MAGIC 0x2AB1EAF

/** chunk size = 24 bytes */
#define	ZAP_LEAF_CHUNKSIZE 24

/**
 * The amount of space available for chunks is:
 * block size (1<<l->l_bs) - hash entry size (2) * number of hash
 * entries - header space (2*chunksize)
 */
#define	ZAP_LEAF_NUMCHUNKS(l) \
	(((1<<(l)->l_bs) - 2*ZAP_LEAF_HASH_NUMENTRIES(l)) / \
	ZAP_LEAF_CHUNKSIZE - 2)

/**
 * The amount of space within the chunk available for the array is:
 * chunk size - space for type (1) - space for next pointer (2)
 */
#define	ZAP_LEAF_ARRAY_BYTES (ZAP_LEAF_CHUNKSIZE - 3)

#define	ZAP_LEAF_ARRAY_NCHUNKS(bytes) \
	(((bytes)+ZAP_LEAF_ARRAY_BYTES-1)/ZAP_LEAF_ARRAY_BYTES)

/**
 * Low water mark:  when there are only this many chunks free, start
 * growing the ptrtbl.  Ideally, this should be larger than a
 * "reasonably-sized" entry.  20 chunks is more than enough for the
 * largest directory entry (MAXNAMELEN (256) byte name, 8-byte value),
 * while still being only around 3% for 16k blocks.
 */
#define	ZAP_LEAF_LOW_WATER (20)

/**
 * The leaf hash table has block size / 2^5 (32) number of entries,
 * which should be more than enough for the maximum number of entries,
 * which is less than block size / CHUNKSIZE (24) / minimum number of
 * chunks per entry (3).
 */
#define	ZAP_LEAF_HASH_SHIFT(l) ((l)->l_bs - 5)
#define	ZAP_LEAF_HASH_NUMENTRIES(l) (1 << ZAP_LEAF_HASH_SHIFT(l))

/**
 * The chunks start immediately after the hash table.  The end of the
 * hash table is at l_hash + HASH_NUMENTRIES, which we simply cast to a
 * chunk_t.
 */
#define	ZAP_LEAF_CHUNK(l, idx) \
	((zap_leaf_chunk_t *) \
	((l)->l_phys->l_hash + ZAP_LEAF_HASH_NUMENTRIES(l)))[idx]
#define	ZAP_LEAF_ENTRY(l, idx) (&ZAP_LEAF_CHUNK(l, idx).l_entry)

typedef enum zap_chunk_type {
	ZAP_CHUNK_FREE = 253,
	ZAP_CHUNK_ENTRY = 252,
	ZAP_CHUNK_ARRAY = 251,
	ZAP_CHUNK_TYPE_MAX = 250
} zap_chunk_type_t;

#define	ZLF_ENTRIES_CDSORTED (1<<0)

/**
 * \note If zap_leaf_phys_t is modified, zap_leaf_byteswap() must be modified.
 */
typedef struct zap_leaf_phys {
	struct zap_leaf_header {
		/**
		 * \name Accessible to ZAP
		 * \{ */
		uint64_t lh_block_type;		/**< ZBT_LEAF */
		uint64_t lh_pad1;
		uint64_t lh_prefix;		/**< hash prefix of this leaf */
		uint32_t lh_magic;		/**< ZAP_LEAF_MAGIC */
		uint16_t lh_nfree;		/**< number free chunks */
		uint16_t lh_nentries;		/**< number of entries */
		uint16_t lh_prefix_len;		/**< num bits used to id this */
		/**
		 * \}
		 * \name Private to zap_leaf
		 * \{ */
		uint16_t lh_freelist;		/**< chunk head of free list */
		uint8_t lh_flags;		/**< ZLF_* flags */
		uint8_t lh_pad2[11];
		/** \} */
	} l_hdr; /**< 2 24-byte chunks */

	/**
	 * The header is followed by a hash table with
	 * ZAP_LEAF_HASH_NUMENTRIES(zap) entries.  The hash table is
	 * followed by an array of ZAP_LEAF_NUMCHUNKS(zap)
	 * zap_leaf_chunk structures.  These structures are accessed
	 * with the ZAP_LEAF_CHUNK() macro.
	 */

	uint16_t l_hash[1];
} zap_leaf_phys_t;

typedef struct zap_leaf_dbuf {
	uint8_t zldb_pad[offsetof(dmu_buf_t, db_data)];
	zap_leaf_phys_t *zldb_data;
} zap_leaf_dbuf_t;

typedef union zap_leaf_chunk {
	struct zap_leaf_entry {
		uint8_t le_type; 		/**< always ZAP_CHUNK_ENTRY */
		uint8_t le_value_intlen;	/**< size of value's ints */
		uint16_t le_next;		/**< next entry in hash chain */
		uint16_t le_name_chunk;		/**< first chunk of the name */
		uint16_t le_name_numints;	/**< ints in name (incl null) */
		uint16_t le_value_chunk;	/**< first chunk of the value */
		uint16_t le_value_numints;	/**< value length in ints */
		uint32_t le_cd;			/**< collision differentiator */
		uint64_t le_hash;		/**< hash value of the name */
	} l_entry;
	struct zap_leaf_array {
		uint8_t la_type;		/**< always ZAP_CHUNK_ARRAY */
		uint8_t la_array[ZAP_LEAF_ARRAY_BYTES];
		uint16_t la_next;		/**< next blk or CHAIN_END */
	} l_array;
	struct zap_leaf_free {
		uint8_t lf_type;		/**< always ZAP_CHUNK_FREE */
		uint8_t lf_pad[ZAP_LEAF_ARRAY_BYTES];
		uint16_t lf_next;	/**< next in free list, or CHAIN_END */
	} l_free;
} zap_leaf_chunk_t;

typedef struct zap_leaf {
	/** Dbuf user eviction data for this instance. */
	dmu_buf_user_t db_evict;
	krwlock_t l_rwlock;
	uint64_t l_blkid;	/**< 1<<ZAP_BLOCK_SHIFT byte block off */
	int l_bs;		/**< block size shift */
	union {
		dmu_buf_t *l_dmu_db;
		zap_leaf_dbuf_t *l_db;
	} zl_db_u;
} zap_leaf_t;

#define	l_dbuf zl_db_u.l_dmu_db
#define	l_phys zl_db_u.l_db->zldb_data

typedef struct zap_entry_handle {
	/**
	 * \name Public
	 * Set by zap_leaf.c and public to zap.c
	 * \{ */
	uint64_t zeh_num_integers;
	uint64_t zeh_hash;
	uint32_t zeh_cd;
	uint8_t zeh_integer_size;

	/**
	 * \}
	 * \name Private
	 * private to zap_leaf.c
	 * \{ */
	uint16_t zeh_fakechunk;
	uint16_t *zeh_chunkp;
	zap_leaf_t *zeh_leaf;
	/** \} */
} zap_entry_handle_t;

/*
 * Routines which manipulate leaf entries.
 */
extern int zap_leaf_lookup(zap_leaf_t *l,
    struct zap_name *zn, zap_entry_handle_t *zeh);
extern int zap_leaf_lookup_closest(zap_leaf_t *l,
    uint64_t hash, uint32_t cd, zap_entry_handle_t *zeh);

extern int zap_entry_read(const zap_entry_handle_t *zeh,
    uint8_t integer_size, uint64_t num_integers, void *buf);
extern int zap_entry_read_name(struct zap *zap, const zap_entry_handle_t *zeh,
    uint16_t buflen, char *buf);
extern int zap_entry_update(zap_entry_handle_t *zeh,
    uint8_t integer_size, uint64_t num_integers, const void *buf);
extern void zap_entry_remove(zap_entry_handle_t *zeh);
extern int zap_entry_create(zap_leaf_t *l, struct zap_name *zn, uint32_t cd,
    uint8_t integer_size, uint64_t num_integers, const void *buf,
    zap_entry_handle_t *zeh);
extern boolean_t zap_entry_normalization_conflict(zap_entry_handle_t *zeh,
    struct zap_name *zn, const char *name, struct zap *zap);

/*
 * Other stuff.
 */

extern void zap_leaf_init(zap_leaf_t *l, boolean_t sort);
extern void zap_leaf_byteswap(zap_leaf_phys_t *buf, int len);
extern void zap_leaf_split(zap_leaf_t *l, zap_leaf_t *nl, boolean_t sort);
extern void zap_leaf_stats(struct zap *zap, zap_leaf_t *l,
    struct zap_stats *zs);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_ZAP_LEAF_H */
