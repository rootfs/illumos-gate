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
 * Copyright (c) 2006 Pawel Jakub Dawidek <pjd@FreeBSD.org>
 * All rights reserved.
 *
 * Portions Copyright (c) 2012 Martin Matuska <mm@FreeBSD.org>
 */

#include <sys/zfs_context.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/bio.h>
#include <sys/disk.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/vdev_impl.h>
#include <sys/fs/zfs.h>
#include <sys/zio.h>
#include <geom/geom.h>
#include <geom/geom_int.h>
#include <machine/_inttypes.h>

/*
 * Virtual device vector for GEOM.
 */

struct g_class zfs_vdev_class = {
	.name = "ZFS::VDEV",
	.version = G_VERSION,
};

DECLARE_GEOM_CLASS(zfs_vdev_class, zfs_vdev);

SYSCTL_DECL(_vfs_zfs_vdev);
/* Don't send BIO_FLUSH. */
static int vdev_geom_bio_flush_disable = 0;
TUNABLE_INT("vfs.zfs.vdev.bio_flush_disable", &vdev_geom_bio_flush_disable);
SYSCTL_INT(_vfs_zfs_vdev, OID_AUTO, bio_flush_disable, CTLFLAG_RW,
    &vdev_geom_bio_flush_disable, 0, "Disable BIO_FLUSH");
/* Don't send BIO_DELETE. */
static int vdev_geom_bio_delete_disable = 0;
TUNABLE_INT("vfs.zfs.vdev.bio_delete_disable", &vdev_geom_bio_delete_disable);
SYSCTL_INT(_vfs_zfs_vdev, OID_AUTO, bio_delete_disable, CTLFLAG_RW,
    &vdev_geom_bio_delete_disable, 0, "Disable BIO_DELETE");

/* Declare local functions */
static void vdev_geom_detach(struct g_consumer *cp);

/*
 * Thread local storage used to indicate when a thread is probing geoms
 * for their guids.  If NULL, this thread is not tasting geoms.  If non NULL,
 * it is looking for a replacement for the vdev_t* that is its value.
 */
extern uint_t zfs_geom_probe_vdev_key;

static void
vdev_geom_orphan(struct g_consumer *cp)
{
	vdev_t *vd;

	g_topology_assert();

	vd = cp->private;
	if (vd == NULL)
		return;

	/*
	 * Orphan callbacks occur from the GEOM event thread.
	 * Concurrent with this call, new I/O requests may be
	 * working their way through GEOM about to find out
	 * (only once executed by the g_down thread) that we've
	 * been orphaned from our disk provider.  These I/Os
	 * must be retired before we can detach our consumer.
	 * This is most easily achieved by acquiring the
	 * SPA ZIO configuration lock as a writer, but doing
	 * so with the GEOM topology lock held would cause
	 * a lock order reversal.  Instead, rely on the SPA's
	 * async removal support to invoke a close on this
	 * vdev once it is safe to do so.
	 */
	vd->vdev_remove_wanted = B_TRUE;
	spa_async_request(vd->vdev_spa, SPA_ASYNC_REMOVE);
}

static int
vdev_geom_populate_physpath(struct g_consumer *cp)
{
	vdev_t *vd;
	int physpath_len;
	char *physpath;
	int error;

	vd = cp->private;
	physpath_len = MAXPATHLEN;
	physpath = g_malloc(physpath_len, M_WAITOK|M_ZERO);
	error = g_io_getattr("GEOM::physpath", cp, &physpath_len, physpath);
	if (error == 0)
		vd->vdev_physpath = spa_strdup(physpath);
	g_free(physpath);
	return (error);
}

static void
vdev_geom_set_physpath(struct g_consumer *cp)
{
	char *old_physpath;
	vdev_t *vd;
	spa_t *spa;
	int error, held_lock;

	if (g_access(cp, 1, 0, 0) != 0)
		return;
	vd = cp->private;
	old_physpath = vd->vdev_physpath;
	error = vdev_geom_populate_physpath(cp);
	g_access(cp, -1, 0, 0);
	if (error != 0)
		return;

	spa = vd->vdev_spa;
	if (old_physpath != NULL) {
		held_lock = spa_config_held(spa, SCL_STATE, RW_WRITER);
		if (held_lock == 0) {
			g_topology_unlock();
			spa_config_enter(spa, SCL_STATE, FTAG, RW_WRITER);
		}

		spa_strfree(old_physpath);

		if (held_lock == 0) {
			spa_config_exit(spa, SCL_STATE, FTAG);
			g_topology_lock();
		}
	}
	/* If the physical path changed, update the config. */
	if (old_physpath == NULL || strcmp(old_physpath, vd->vdev_physpath) !=0)
		spa_async_request(spa, SPA_ASYNC_CONFIG_UPDATE);
}

static void
vdev_geom_attrchanged(struct g_consumer *cp, const char *attr)
{
	vdev_t *vd;
	char *old_physpath;
	int error;

	vd = cp->private;
	if (vd == NULL)
		return;

	if (strcmp(attr, "GEOM::physpath") == 0) {
		vdev_geom_set_physpath(cp);
		return;
	}
}

static struct g_consumer *
vdev_geom_attach(struct g_provider *pp, vdev_t *vd)
{
	struct g_geom *gp;
	struct g_consumer *cp;
	int error;

	g_topology_assert();

	ZFS_LOG(1, "Attaching to %s.", pp->name);

	if (pp->sectorsize > VDEV_PAD_SIZE || !ISP2(pp->sectorsize)) {
		ZFS_LOG(1, "Failing attach of %s. Incompatible sectorsize %d\n",
		    pp->name, pp->sectorsize);
		return (NULL);
	}

	/* Do we have geom already? No? Create one. */
	LIST_FOREACH(gp, &zfs_vdev_class.geom, geom) {
		if (gp->flags & G_GEOM_WITHER)
			continue;
		if (strcmp(gp->name, "zfs::vdev") != 0)
			continue;
		break;
	}
	if (gp == NULL) {
		gp = g_new_geomf(&zfs_vdev_class, "zfs::vdev");
		gp->orphan = vdev_geom_orphan;
		gp->attrchanged = vdev_geom_attrchanged;
	}
	cp = g_new_consumer(gp);
	error = g_attach(cp, pp);
	if (error != 0) {
		printf("%s(%d): g_attach failed: %d\n", __func__,
		       __LINE__, error);
		vdev_geom_detach(cp);
		return (NULL);
	}
	error = g_access(cp, /*r*/1, /*w*/0, /*e*/0);
	if (error != 0) {
		printf("%s(%d): g_access failed: %d\n", __func__,
		       __LINE__, error);
		vdev_geom_detach(cp);
		return (NULL);
	}
	ZFS_LOG(1, "Created consumer for %s.", pp->name);

	cp->private = vd;
	if (vd != NULL) {
		vd->vdev_tsd = cp;
		/*
		 * Initially populate the physical path if needed.  If there
		 * is already a physical path, then there are consumers
		 * available to request a config update if needed.
		 */
		if (vd->vdev_physpath == NULL)
			(void) vdev_geom_populate_physpath(cp);
	}

	return (cp);
}

static void
vdev_geom_detach(struct g_consumer *cp)
{
	struct g_geom *gp;
	vdev_t *vd;

	g_topology_assert();

	ZFS_LOG(1, "Detaching consumer. Provider %s.",
	    cp->provider->name ? cp->provider->name : "NULL");

	vd = cp->private;
	if (vd != NULL)
		vd->vdev_tsd = NULL;
	cp->private = NULL;

	gp = cp->geom;
	if (cp->acr > 0)
		g_access(cp, -1, 0, 0);
	/* Destroy consumer on last close. */
	if (cp->acr == 0 && cp->ace == 0) {
		if (cp->acw > 0)
			g_access(cp, 0, -cp->acw, 0);
		if (cp->provider != NULL) {
			ZFS_LOG(1, "Destroying consumer of %s.",
			    cp->provider->name);
			g_detach(cp);
		}
		g_destroy_consumer(cp);
	}
	/* Destroy geom if there are no consumers left. */
	if (LIST_EMPTY(&gp->consumer)) {
		ZFS_LOG(1, "Destroyed geom %s.", gp->name);
		g_wither_geom(gp, ENXIO);
	}
}

static void
vdev_geom_close_locked(vdev_t *vd)
{
	struct g_consumer *cp;

	g_topology_assert();

	cp = vd->vdev_tsd;
	if (cp == NULL)
		return;

	ZFS_LOG(1, "Closing access to %s.", cp->provider->name);
	KASSERT(vd->vdev_tsd == cp, ("%s: vdev_tsd is not cp", __func__));
	KASSERT(cp->private == vd, ("%s: cp->private is not vd", __func__));

	vdev_geom_detach(cp);
}

static void
nvlist_get_guids(nvlist_t *list, uint64_t *pguid, uint64_t *vguid)
{
	nvpair_t *elem = NULL;

	*vguid = 0;
	*pguid = 0;
	while ((elem = nvlist_next_nvpair(list, elem)) != NULL) {
		if (nvpair_type(elem) != DATA_TYPE_UINT64)
			continue;

		if (strcmp(nvpair_name(elem), ZPOOL_CONFIG_POOL_GUID) == 0) {
			VERIFY(nvpair_value_uint64(elem, pguid) == 0);
		} else if (strcmp(nvpair_name(elem), ZPOOL_CONFIG_GUID) == 0) {
			VERIFY(nvpair_value_uint64(elem, vguid) == 0);
		}

		if (*pguid != 0 && *vguid != 0)
			break;
	}
}

/*
 * Issue one or more bios to the vdev in parallel
 * cmds, datas, offsets, and sizes are arrays of length ncmds.  Each IO
 * operation is described by paralllel entries from each array.  There may be
 * more bios actually issued than entries in the array
 */
static int
vdev_geom_io(struct g_consumer *cp, int *cmds, void **datas, off_t *offsets,
    off_t *sizes, int ncmds)
{
	struct bio **bios;
	u_char *p;
	off_t off, maxio, s, end;
	int error, i, n_bios, j;
	size_t bios_size;

	maxio = MAXPHYS - (MAXPHYS % cp->provider->sectorsize);
	error = 0;
	n_bios = 0;
	j = 0;

	/* How many bios are required for all commands ? */
	for (i = 0; i < ncmds; i++)
		n_bios += (sizes[i] + maxio - 1) / maxio;

	/* Allocate memory for the bios */
	bios_size = n_bios * sizeof(struct bio*);
	bios = kmem_alloc(bios_size, KM_SLEEP);
	bzero(bios, bios_size);

	/* Prepare and issue all of the bios */
	for (i = 0; i < ncmds; i++) {
		off = offsets[i];
		p = datas[i];
		s = sizes[i];
		end = off + s;
		ASSERT((off % cp->provider->sectorsize) == 0);
		ASSERT((s % cp->provider->sectorsize) == 0);

		for (; off < end; off += maxio, p += maxio, s -= maxio) {
			bios[j] = g_alloc_bio();
			bzero(bios[j], sizeof(*bios[j]));
			bios[j]->bio_cmd = cmds[i];
			bios[j]->bio_done = NULL;
			bios[j]->bio_offset = off;
			bios[j]->bio_length = MIN(s, maxio);
			bios[j]->bio_data = p;
			g_io_request(bios[j], cp);
			j++;
		}
	}
	ASSERT(j == n_bios);

	/* Wait for all of the bios to complete, and clean them up */
	for (j=0; j < n_bios; j++) {
		if (error == 0)
			error = biowait(bios[j], "vdev_geom_io");
		else
			biowait(bios[j], "vdev_geom_io");
		g_destroy_bio(bios[j]);
	}
	kmem_free(bios, bios_size);

	return (error);
}

static int
vdev_geom_read_config(struct g_consumer *cp, nvlist_t **config)
{
	struct g_provider *pp;
	vdev_phys_t *vdev_lists[VDEV_LABELS];
	char *p, *buf;
	size_t buflen;
	uint64_t psize, state, txg;
	off_t offsets[VDEV_LABELS];
	off_t size;
	off_t sizes[VDEV_LABELS];
	int cmds[VDEV_LABELS];
	int error, l, len;

	g_topology_assert_not();

	pp = cp->provider;
	ZFS_LOG(1, "Reading config from %s...", pp->name);

	psize = pp->mediasize;
	psize = P2ALIGN(psize, (uint64_t)sizeof(vdev_label_t));

	size = sizeof(*vdev_lists[0]) + pp->sectorsize -
	    ((sizeof(*vdev_lists[0]) - 1) % pp->sectorsize) - 1;

	buflen = sizeof(vdev_lists[0]->vp_nvlist);

	*config = NULL;
	/* Create all of the IO requests */
	for (l = 0; l < VDEV_LABELS; l++) {
		cmds[l] = BIO_READ;
		vdev_lists[l] = kmem_alloc(size, KM_SLEEP);
		offsets[l] = vdev_label_offset(psize, l, 0) + VDEV_SKIP_SIZE;
		sizes[l] = size;
		ASSERT(offsets[l] % pp->sectorsize == 0);
	}

	/* Issue the IO requests */
	error = vdev_geom_io(cp, cmds, (void**)vdev_lists, offsets, sizes,
	    VDEV_LABELS);

	/* Parse the labels */
	for (l = 0; l < VDEV_LABELS; l++) {
		if (error != 0)
			continue;

		buf = vdev_lists[l]->vp_nvlist;

		if (nvlist_unpack(buf, buflen, config, 0) != 0)
			continue;

		if (nvlist_lookup_uint64(*config, ZPOOL_CONFIG_POOL_STATE,
		    &state) != 0 || state > POOL_STATE_L2CACHE) {
			nvlist_free(*config);
			*config = NULL;
			continue;
		}

		if (state != POOL_STATE_SPARE && state != POOL_STATE_L2CACHE &&
		    (nvlist_lookup_uint64(*config, ZPOOL_CONFIG_POOL_TXG,
		    &txg) != 0 || txg == 0)) {
			nvlist_free(*config);
			*config = NULL;
			continue;
		}

		break;
	}

	/* Free the label storage */
	for (l = 0; l < VDEV_LABELS; l++)
		kmem_free(vdev_lists[l], size);

	return (*config == NULL ? ENOENT : 0);
}

static void
resize_configs(nvlist_t ***configs, uint64_t *count, uint64_t id)
{
	nvlist_t **new_configs;
	uint64_t i;

	if (id < *count)
		return;
	new_configs = kmem_zalloc((id + 1) * sizeof(nvlist_t *),
	    KM_SLEEP);
	for (i = 0; i < *count; i++)
		new_configs[i] = (*configs)[i];
	if (*configs != NULL)
		kmem_free(*configs, *count * sizeof(void *));
	*configs = new_configs;
	*count = id + 1;
}

static void
process_vdev_config(nvlist_t ***configs, uint64_t *count, nvlist_t *cfg,
    const char *name, uint64_t *known_pool_guid)
{
	nvlist_t *vdev_tree;
	uint64_t pool_guid;
	uint64_t vdev_guid, known_guid;
	uint64_t id, txg, known_txg;
	char *pname;
	int i;

	if (nvlist_lookup_string(cfg, ZPOOL_CONFIG_POOL_NAME, &pname) != 0 ||
	    strcmp(pname, name) != 0)
		goto ignore;

	if (nvlist_lookup_uint64(cfg, ZPOOL_CONFIG_POOL_GUID, &pool_guid) != 0)
		goto ignore;

	if (nvlist_lookup_uint64(cfg, ZPOOL_CONFIG_TOP_GUID, &vdev_guid) != 0)
		goto ignore;

	if (nvlist_lookup_nvlist(cfg, ZPOOL_CONFIG_VDEV_TREE, &vdev_tree) != 0)
		goto ignore;

	if (nvlist_lookup_uint64(vdev_tree, ZPOOL_CONFIG_ID, &id) != 0)
		goto ignore;

	VERIFY(nvlist_lookup_uint64(cfg, ZPOOL_CONFIG_POOL_TXG, &txg) == 0);

	if (*known_pool_guid != 0) {
		if (pool_guid != *known_pool_guid)
			goto ignore;
	} else
		*known_pool_guid = pool_guid;

	resize_configs(configs, count, id);

	if ((*configs)[id] != NULL) {
		VERIFY(nvlist_lookup_uint64((*configs)[id],
		    ZPOOL_CONFIG_POOL_TXG, &known_txg) == 0);
		if (txg <= known_txg)
			goto ignore;
		nvlist_free((*configs)[id]);
	}

	(*configs)[id] = cfg;
	return;

ignore:
	nvlist_free(cfg);
}

int
vdev_geom_read_pool_label(const char *name,
    nvlist_t ***configs, uint64_t *count)
{
	struct g_class *mp;
	struct g_geom *gp;
	struct g_provider *pp;
	struct g_consumer *zcp;
	nvlist_t *vdev_cfg;
	uint64_t pool_guid;
	int error;

	DROP_GIANT();
	g_topology_lock();

	*configs = NULL;
	*count = 0;
	pool_guid = 0;
	LIST_FOREACH(mp, &g_classes, class) {
		if (mp == &zfs_vdev_class)
			continue;
		LIST_FOREACH(gp, &mp->geom, geom) {
			if (gp->flags & G_GEOM_WITHER)
				continue;
			LIST_FOREACH(pp, &gp->provider, provider) {
				if (pp->flags & G_PF_WITHER)
					continue;
				zcp = vdev_geom_attach(pp, NULL);
				if (zcp == NULL)
					continue;
				g_topology_unlock();
				error = vdev_geom_read_config(zcp, &vdev_cfg);
				g_topology_lock();
				vdev_geom_detach(zcp);
				if (error)
					continue;
				ZFS_LOG(1, "successfully read vdev config");

				process_vdev_config(configs, count,
				    vdev_cfg, name, &pool_guid);
			}
		}
	}
	g_topology_unlock();
	PICKUP_GIANT();

	return (*count > 0 ? 0 : ENOENT);
}

static void
vdev_geom_read_guids(struct g_consumer *cp, uint64_t *pguid, uint64_t *vguid)
{
	nvlist_t *config;

	g_topology_assert_not();
	*pguid = 0;
	*vguid = 0;

	if (vdev_geom_read_config(cp, &config) == 0) {
		nvlist_get_guids(config, pguid, vguid);
		nvlist_free(config);
	}
}

static boolean_t
vdev_attach_ok(vdev_t *vd, struct g_provider *pp)
{
	uint64_t pool_guid;
	uint64_t vdev_guid;
	struct g_consumer *zcp;
	boolean_t pool_ok;
	boolean_t vdev_ok;

	zcp = vdev_geom_attach(pp, NULL);
	if (zcp == NULL) {
		ZFS_LOG(1, "Unable to attach tasting instance to %s.",
		    pp->name);
		return (B_FALSE);
	}
	g_topology_unlock();
	vdev_geom_read_guids(zcp, &pool_guid, &vdev_guid);
	g_topology_lock();
	vdev_geom_detach(zcp);

	/* Spares can be assigned to multiple pools. */
	pool_ok = vd->vdev_isspare || pool_guid == spa_guid(vd->vdev_spa);
	vdev_ok = vdev_guid == vd->vdev_guid;
	if (pool_ok && vdev_ok) {
		ZFS_LOG(1, "guids match for provider %s.", vd->vdev_path);
	} else {
		ZFS_LOG(1, "guid mismatch for provider %s: "
		    "%ju:%ju != %ju:%ju.", vd->vdev_path,
		    (uintmax_t)spa_guid(vd->vdev_spa),
		    (uintmax_t)vd->vdev_guid,
		    (uintmax_t)pool_guid, (uintmax_t)vdev_guid);
	}
	return (pool_ok && vdev_ok);
}

static struct g_consumer *
vdev_geom_attach_by_guids(vdev_t *vd)
{
	struct g_class *mp;
	struct g_geom *gp;
	struct g_provider *pp;
	struct g_consumer *cp;

	g_topology_assert();

	cp = NULL;
	LIST_FOREACH(mp, &g_classes, class) {
		if (mp == &zfs_vdev_class)
			continue;
		LIST_FOREACH(gp, &mp->geom, geom) {
			if (gp->flags & G_GEOM_WITHER)
				continue;
			LIST_FOREACH(pp, &gp->provider, provider) {
				if (!vdev_attach_ok(vd, pp))
					continue;
				cp = vdev_geom_attach(pp, vd);
				if (cp == NULL) {
					printf("ZFS WARNING: Unable to attach "
					    "to %s.\n", pp->name);
					continue;
				}
				break;
			}
			if (cp != NULL)
				break;
		}
		if (cp != NULL)
			break;
	}
end:
	return (cp);
}

static struct g_consumer *
vdev_geom_open_by_guids(vdev_t *vd)
{
	struct g_consumer *cp;
	char *buf;
	size_t len;

	g_topology_assert();

	ZFS_LOG(1, "Searching by guids [%ju:%ju].",
	    (uintmax_t)spa_guid(vd->vdev_spa), (uintmax_t)vd->vdev_guid);
	cp = vdev_geom_attach_by_guids(vd);
	if (cp != NULL) {
		len = strlen(cp->provider->name) + strlen("/dev/") + 1;
		buf = kmem_alloc(len, KM_SLEEP);

		snprintf(buf, len, "/dev/%s", cp->provider->name);
		spa_strfree(vd->vdev_path);
		vd->vdev_path = buf;

		ZFS_LOG(1, "Attach by guids [%ju:%ju] succeeded, provider %s.",
		    (uintmax_t)spa_guid(vd->vdev_spa),
		    (uintmax_t)vd->vdev_guid, vd->vdev_path);
	} else {
		ZFS_LOG(1, "Search by guids [%ju:%ju] failed.",
		    (uintmax_t)spa_guid(vd->vdev_spa),
		    (uintmax_t)vd->vdev_guid);
	}

	return (cp);
}

static struct g_consumer *
vdev_geom_open_by_path(vdev_t *vd, int check_guid)
{
	struct g_provider *pp;
	struct g_consumer *cp;

	g_topology_assert();

	ZFS_LOG(1, "Opening by path %s%s", vd->vdev_path,
	    check_guid ? " with GUID verification." : "");

	cp = NULL;
	pp = g_provider_by_name(vd->vdev_path + sizeof("/dev/") - 1);
	if (pp != NULL) {
		ZFS_LOG(1, "Found provider by name %s.", vd->vdev_path);
		if (!check_guid || vdev_attach_ok(vd, pp))
			cp = vdev_geom_attach(pp, vd);
	}

	return (cp);
}

static int
vdev_geom_open(vdev_t *vd, uint64_t *psize, uint64_t *max_psize,
    uint64_t *logical_ashift, uint64_t *physical_ashift)
{
	struct g_provider *pp;
	struct g_consumer *cp;
	size_t bufsize;
	int error;

	/*
	 * We must have a pathname, and it must be absolute.
	 */
	if (vd->vdev_path == NULL || vd->vdev_path[0] != '/') {
		vd->vdev_stat.vs_aux = VDEV_AUX_BAD_LABEL;
		return (EINVAL);
	}

	vd->vdev_tsd = NULL;

	DROP_GIANT();
	g_topology_lock();
	error = 0;

	/* Set the TLS to indicate downstack that we should not access zvols*/
	VERIFY(tsd_set(zfs_geom_probe_vdev_key, vd) == 0);

	if (vd->vdev_spa->spa_splitting_newspa == B_TRUE ||
	    (vd->vdev_prevstate == VDEV_STATE_UNKNOWN &&
	     vd->vdev_spa->spa_load_state == SPA_LOAD_NONE)) {
		/*
		 * We are dealing with a vdev that hasn't been previously
		 * opened (since boot), and we are not loading an
		 * existing pool configuration (e.g. this operations is
		 * an add of a vdev to new or * existing pool) or we are
		 * in the process of splitting a pool.  Find the GEOM
		 * provider by its name, ignoring GUID mismatches.
		 *
		 * XXPOLICY: It would be safer to only allow a device
		 *           that is unlabeled or labeled but missing
		 *           GUID information to be opened in this fashion,
		 *           unless we are doing a split, in which case we
		 *           should allow any guid.
		 */
		cp = vdev_geom_open_by_path(vd, 0);
	} else {
		/*
		 * Try using the recorded path for this device, but only
		 * accept it if its label data contains the expected GUIDs.
		 */
		cp = vdev_geom_open_by_path(vd, 1);
		if (cp == NULL) {
			/*
			 * The device at vd->vdev_path doesn't have the
			 * expected GUIDs. The disks might have merely
			 * moved around so try all other GEOM providers
			 * to find one with the right GUIDs.
			 */
			cp = vdev_geom_open_by_guids(vd);
		}
	}

	/* Clear the TLS now that tasting is done */
	VERIFY(tsd_set(zfs_geom_probe_vdev_key, NULL) == 0);

	if (cp == NULL) {
		ZFS_LOG(1, "Provider %s not found.", vd->vdev_path);
		error = ENOENT;
	} else if (cp->provider->sectorsize > VDEV_PAD_SIZE ||
	    !ISP2(cp->provider->sectorsize)) {
		ZFS_LOG(1, "Provider %s has unsupported sectorsize.",
		    vd->vdev_path);
		vdev_geom_close_locked(vd);
		error = EINVAL;
		cp = NULL;
	} else if (cp->acw == 0 && (spa_mode(vd->vdev_spa) & FWRITE) != 0) {
		int i;

		for (i = 0; i < 5; i++) {
			error = g_access(cp, 0, 1, 0);
			if (error == 0)
				break;
			g_topology_unlock();
			tsleep(vd, 0, "vdev", hz / 2);
			g_topology_lock();
		}
		if (error != 0) {
			printf("ZFS WARNING: Error %d opening %s for write.\n",
			    error, vd->vdev_path);
			vdev_geom_close_locked(vd);
			cp = NULL;
		}
	}

	g_topology_unlock();
	PICKUP_GIANT();

	if (cp == NULL) {
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
		return (error);
	}
	pp = cp->provider;

	/*
	 * Determine the actual size of the device.
	 */
	*max_psize = *psize = pp->mediasize;

	/*
	 * Determine the device's minimum transfer size and preferred
	 * transfer size.
	 */
	*logical_ashift = highbit(MAX(pp->sectorsize, SPA_MINBLOCKSIZE)) - 1;
	*physical_ashift = 0;
	if (pp->stripesize)
		*physical_ashift = highbit(pp->stripesize) - 1;

	/*
	 * Clear the nowritecache settings, so that on a vdev_reopen()
	 * we will try again.
	 */
	vd->vdev_nowritecache = B_FALSE;

	return (0);
}

static void
vdev_geom_close(vdev_t *vd)
{
	DROP_GIANT();
	g_topology_lock();
	vdev_geom_close_locked(vd);
	g_topology_unlock();
	PICKUP_GIANT();
}

static void
vdev_geom_io_intr(struct bio *bp)
{
	vdev_t *vd;
	zio_t *zio;

	zio = bp->bio_caller1;
	vd = zio->io_vd;
	zio->io_error = bp->bio_error;
	if (zio->io_error == 0 && bp->bio_resid != 0)
		zio->io_error = EIO;
	if (bp->bio_cmd == BIO_FLUSH && bp->bio_error == ENOTSUP) {
		/*
		 * If we get ENOTSUP, we know that no future
		 * attempts will ever succeed.  In this case we
		 * set a persistent bit so that we don't bother
		 * with the ioctl in the future.
		 */
		vd->vdev_nowritecache = B_TRUE;
	}
	if (bp->bio_cmd == BIO_DELETE && bp->bio_error == ENOTSUP) {
		/*
		 * If we get ENOTSUP, we know that no future
		 * attempts will ever succeed.  In this case we
		 * set a persistent bit so that we don't bother
		 * with the ioctl in the future.
		 */
		vd->vdev_notrim = B_TRUE;
	}
	if (zio->io_error == EIO && !vd->vdev_remove_wanted) {
		/*
		 * If provider's error is set we assume it is being
		 * removed.
		 */
		if (bp->bio_to->error != 0) {
			/*
			 * We post the resource as soon as possible, instead of
			 * when the async removal actually happens, because the
			 * DE is using this information to discard previous I/O
			 * errors.
			 */
			/* XXX: zfs_post_remove() can sleep. */
			zfs_post_remove(zio->io_spa, vd);
			vd->vdev_remove_wanted = B_TRUE;
			spa_async_request(zio->io_spa, SPA_ASYNC_REMOVE);
		} else if (!vd->vdev_delayed_close) {
			vd->vdev_delayed_close = B_TRUE;
		}
	}
	g_destroy_bio(bp);
	zio_interrupt(zio);
}

static int
vdev_geom_io_start(zio_t *zio)
{
	vdev_t *vd;
	struct g_consumer *cp;
	struct bio *bp;
	int error;

	vd = zio->io_vd;

	if (zio->io_type == ZIO_TYPE_IOCTL) {
		/* XXPOLICY */
		if (!vdev_readable(vd)) {
			zio->io_error = ENXIO;
			return (ZIO_PIPELINE_CONTINUE);
		}

		switch (zio->io_cmd) {
		case DKIOCFLUSHWRITECACHE:
			if (zfs_nocacheflush || vdev_geom_bio_flush_disable)
				break;
			if (vd->vdev_nowritecache) {
				zio->io_error = ENOTSUP;
				break;
			}
			goto sendreq;
#ifdef NOTYET
		case DKIOCTRIM:
			if (vdev_geom_bio_delete_disable)
				break;
			if (vd->vdev_notrim) {
				zio->io_error = ENOTSUP;
				break;
			}
			goto sendreq;
#endif
		default:
			zio->io_error = ENOTSUP;
		}

		return (ZIO_PIPELINE_CONTINUE);
	}
sendreq:
	cp = vd->vdev_tsd;
	if (cp == NULL) {
		zio->io_error = ENXIO;
		return (ZIO_PIPELINE_CONTINUE);
	}
	bp = g_alloc_bio();
	bp->bio_caller1 = zio;
	switch (zio->io_type) {
	case ZIO_TYPE_READ:
	case ZIO_TYPE_WRITE:
		bp->bio_cmd = zio->io_type == ZIO_TYPE_READ ? BIO_READ : BIO_WRITE;
		bp->bio_data = zio->io_data;
		bp->bio_offset = zio->io_offset;
		bp->bio_length = zio->io_size;
		break;
	case ZIO_TYPE_IOCTL:
		switch (zio->io_cmd) {
		case DKIOCFLUSHWRITECACHE:
			bp->bio_cmd = BIO_FLUSH;
			bp->bio_flags |= BIO_ORDERED;
			bp->bio_data = NULL;
			bp->bio_offset = cp->provider->mediasize;
			bp->bio_length = 0;
			break;
		case DKIOCTRIM:
			bp->bio_cmd = BIO_DELETE;
			bp->bio_data = NULL;
			bp->bio_offset = zio->io_offset;
			bp->bio_length = zio->io_size;
			break;
		}
		break;
	}
	bp->bio_done = vdev_geom_io_intr;

	g_io_request(bp, cp);

	return (ZIO_PIPELINE_STOP);
}

static void
vdev_geom_io_done(zio_t *zio)
{
}

static void
vdev_geom_hold(vdev_t *vd)
{
}

static void
vdev_geom_rele(vdev_t *vd)
{
}

/*
 * Vector table for the vdev_geom module.
 * This is the only entry point for vdev_geom.
 */
vdev_ops_t vdev_geom_ops = {
	vdev_geom_open,
	vdev_geom_close,
	vdev_default_asize,
	vdev_geom_io_start,
	vdev_geom_io_done,
	NULL,
	vdev_geom_hold,
	vdev_geom_rele,
	VDEV_TYPE_DISK,		/* name of this vdev type */
	B_TRUE			/* leaf vdev */
};
