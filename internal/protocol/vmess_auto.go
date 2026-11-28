package protocol

import (
	"crypto/md5"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"
)

// legacyAuthWindow is the accepted clock offset for legacy MD5 AuthIDs. V2Ray-style
// legacy clients randomize their timestamp by up to ±30 seconds; matching AEAD's ±120s
// window covers real-world client clock drift while remaining cheap in the shared noscan ring.
const (
	legacyAuthWindow = 120
	legacyWindowSize = 2*legacyAuthWindow + 1 // 241 per-second buckets
)

// hmacMD5Stamp computes HMAC-MD5(key=uuid, msg=stamp) purely on the stack with
// zero heap allocations, replacing per-user `hmac.New(md5.New, ...)` allocations.
func hmacMD5Stamp(key [16]byte, stamp [8]byte) [16]byte {
	var innerBuf [64 + 8]byte
	for i := 0; i < 16; i++ {
		innerBuf[i] = key[i] ^ 0x36
	}
	for i := 16; i < 64; i++ {
		innerBuf[i] = 0x36
	}
	copy(innerBuf[64:], stamp[:])
	inner := md5.Sum(innerBuf[:])

	var outerBuf [64 + 16]byte
	for i := 0; i < 16; i++ {
		outerBuf[i] = key[i] ^ 0x5c
	}
	for i := 16; i < 64; i++ {
		outerBuf[i] = 0x5c
	}
	copy(outerBuf[64:], inner[:])
	return md5.Sum(outerBuf[:])
}

// legacySlotVal is pointer-free (noscan) so Go GC never scans the lookup map.
type legacySlotVal struct {
	uuidIdx uint32
	tsOff   int32 // ts - baseTS
}

type legacyUUIDSlot struct {
	uuid   [16]byte
	refs   uint32
	active bool
}

type legacySecondBucket struct {
	ts    int64
	valid bool
	keys  []uint64 // pointer-free noscan slice reused across slides
}

type legacyPrecomputedEntry struct {
	k uint64
	v legacySlotVal
}

type legacyPrecomputedSec struct {
	ts      int64
	entries []legacyPrecomputedEntry
}

type legacyActiveUUID struct {
	idx  uint32
	uuid [16]byte
}

// legacyRing stores a sliding 241-second window of pointer-free HMAC-MD5 AuthIDs
// indexed by the first 64 bits of the 128-bit AuthID, with full 128-bit verification
// and collision overflow handling on lookup.
type legacyRing struct {
	mu sync.RWMutex

	baseTS    int64
	hasWindow bool
	winStart  int64
	winEnd    int64
	uuidGen   uint64

	uuids     []legacyUUIDSlot
	freeUUIDs []uint32
	uuidToIdx map[[16]byte]uint32
	index     map[uint64]legacySlotVal
	overflow  map[uint64][]legacySlotVal
	buckets   [legacyWindowSize]legacySecondBucket

	// Reusable scratch buffers for off-lock 1-second tick computation (only used by ticker).
	tickMu      sync.Mutex
	tickUUIDs   []legacyActiveUUID
	tickEntries []legacyPrecomputedEntry
}

func bucketSlot(ts int64) int {
	s := int(ts % legacyWindowSize)
	if s < 0 {
		s += legacyWindowSize
	}
	return s
}

func (r *legacyRing) ensureInitLocked() {
	if r.uuidToIdx == nil {
		r.uuidToIdx = make(map[[16]byte]uint32)
	}
	if r.index == nil {
		r.index = make(map[uint64]legacySlotVal)
	}
}

func (r *legacyRing) reset() {
	r.tickMu.Lock()
	defer r.tickMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.baseTS = 0
	r.hasWindow = false
	r.winStart = 0
	r.winEnd = 0
	r.uuidGen++
	r.uuids = nil
	r.freeUUIDs = nil
	r.uuidToIdx = nil
	r.index = nil
	r.overflow = nil
	for i := range r.buckets {
		r.buckets[i] = legacySecondBucket{}
	}
}

func (r *legacyRing) insertEntryLocked(k uint64, v legacySlotVal) {
	if cur, exists := r.index[k]; !exists {
		r.index[k] = v
		return
	} else if cur == v {
		return
	}
	if r.overflow == nil {
		r.overflow = make(map[uint64][]legacySlotVal)
	}
	for _, e := range r.overflow[k] {
		if e == v {
			return
		}
	}
	r.overflow[k] = append(r.overflow[k], v)
}

func (r *legacyRing) deleteEntryLocked(k uint64, v legacySlotVal) {
	if cur, exists := r.index[k]; exists && cur == v {
		if ov := r.overflow[k]; len(ov) > 0 {
			last := ov[len(ov)-1]
			ov = ov[:len(ov)-1]
			if len(ov) == 0 {
				delete(r.overflow, k)
			} else {
				r.overflow[k] = ov
			}
			r.index[k] = last
		} else {
			delete(r.index, k)
		}
		return
	}
	if ov := r.overflow[k]; len(ov) > 0 {
		for i, e := range ov {
			if e == v {
				ov[i] = ov[len(ov)-1]
				ov = ov[:len(ov)-1]
				if len(ov) == 0 {
					delete(r.overflow, k)
				} else {
					r.overflow[k] = ov
				}
				return
			}
		}
	}
}

func (r *legacyRing) evictBucketLocked(slot int) {
	b := &r.buckets[slot]
	if !b.valid {
		return
	}
	tsOff := int32(b.ts - r.baseTS)
	for _, k := range b.keys {
		if cur, ok := r.index[k]; ok && cur.tsOff == tsOff {
			if ov := r.overflow[k]; len(ov) > 0 {
				kept := ov[:0]
				for _, e := range ov {
					if e.tsOff != tsOff {
						kept = append(kept, e)
					}
				}
				if len(kept) > 0 {
					r.index[k] = kept[len(kept)-1]
					kept = kept[:len(kept)-1]
					if len(kept) == 0 {
						delete(r.overflow, k)
					} else {
						r.overflow[k] = kept
					}
				} else {
					delete(r.overflow, k)
					delete(r.index, k)
				}
			} else {
				delete(r.index, k)
			}
		} else if ov := r.overflow[k]; len(ov) > 0 {
			kept := ov[:0]
			for _, e := range ov {
				if e.tsOff != tsOff {
					kept = append(kept, e)
				}
			}
			if len(kept) == 0 {
				delete(r.overflow, k)
			} else {
				r.overflow[k] = kept
			}
		}
	}
	b.keys = b.keys[:0]
	b.valid = false
}

func (r *legacyRing) populateSecondLocked(ts int64) {
	slot := bucketSlot(ts)
	b := &r.buckets[slot]
	if b.valid {
		if b.ts == ts {
			return
		}
		r.evictBucketLocked(slot)
	}
	var stamp [8]byte
	binary.BigEndian.PutUint64(stamp[:], uint64(ts))
	tsOff := int32(ts - r.baseTS)
	activeCount := len(r.uuidToIdx)
	if cap(b.keys) < activeCount {
		b.keys = make([]uint64, 0, activeCount)
	} else {
		b.keys = b.keys[:0]
	}
	for i := range r.uuids {
		if !r.uuids[i].active {
			continue
		}
		tag := hmacMD5Stamp(r.uuids[i].uuid, stamp)
		k := binary.LittleEndian.Uint64(tag[:8])
		r.insertEntryLocked(k, legacySlotVal{uuidIdx: uint32(i), tsOff: tsOff})
		b.keys = append(b.keys, k)
	}
	b.ts = ts
	b.valid = true
}

func (r *legacyRing) rebuildAllLocked(now int64) {
	r.ensureInitLocked()
	clear(r.index)
	clear(r.overflow)
	for i := range r.buckets {
		r.buckets[i].keys = r.buckets[i].keys[:0]
		r.buckets[i].valid = false
	}
	r.baseTS = now
	r.winStart = now - legacyAuthWindow
	r.winEnd = now + legacyAuthWindow
	r.hasWindow = true
	if len(r.uuidToIdx) == 0 {
		for ts := r.winStart; ts <= r.winEnd; ts++ {
			slot := bucketSlot(ts)
			r.buckets[slot].ts = ts
			r.buckets[slot].valid = true
		}
		return
	}
	for ts := r.winStart; ts <= r.winEnd; ts++ {
		r.populateSecondLocked(ts)
	}
}

func (r *legacyRing) addUUID(uuid [16]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addUUIDLocked(uuid)
}

func (r *legacyRing) addUUIDLocked(uuid [16]byte) {
	r.ensureInitLocked()
	if uIdx, ok := r.uuidToIdx[uuid]; ok {
		r.uuids[uIdx].refs++
		return
	}
	var uIdx uint32
	if n := len(r.freeUUIDs); n > 0 {
		uIdx = r.freeUUIDs[n-1]
		r.freeUUIDs = r.freeUUIDs[:n-1]
		r.uuids[uIdx] = legacyUUIDSlot{uuid: uuid, refs: 1, active: true}
	} else {
		uIdx = uint32(len(r.uuids))
		r.uuids = append(r.uuids, legacyUUIDSlot{uuid: uuid, refs: 1, active: true})
	}
	r.uuidToIdx[uuid] = uIdx
	r.uuidGen++

	if r.hasWindow {
		var stamp [8]byte
		for ts := r.winStart; ts <= r.winEnd; ts++ {
			binary.BigEndian.PutUint64(stamp[:], uint64(ts))
			tag := hmacMD5Stamp(uuid, stamp)
			k := binary.LittleEndian.Uint64(tag[:8])
			tsOff := int32(ts - r.baseTS)
			r.insertEntryLocked(k, legacySlotVal{uuidIdx: uIdx, tsOff: tsOff})
			slot := bucketSlot(ts)
			r.buckets[slot].keys = append(r.buckets[slot].keys, k)
		}
	}
}

func (r *legacyRing) removeUUIDLocked(uuid [16]byte) {
	uIdx, ok := r.uuidToIdx[uuid]
	if !ok {
		return
	}
	if r.uuids[uIdx].refs > 1 {
		r.uuids[uIdx].refs--
		return
	}
	delete(r.uuidToIdx, uuid)
	r.uuids[uIdx].refs = 0
	r.uuids[uIdx].active = false
	r.freeUUIDs = append(r.freeUUIDs, uIdx)
	r.uuidGen++

	if r.hasWindow {
		var stamp [8]byte
		for ts := r.winStart; ts <= r.winEnd; ts++ {
			binary.BigEndian.PutUint64(stamp[:], uint64(ts))
			tag := hmacMD5Stamp(uuid, stamp)
			k := binary.LittleEndian.Uint64(tag[:8])
			r.deleteEntryLocked(k, legacySlotVal{uuidIdx: uIdx, tsOff: int32(ts - r.baseTS)})
		}
	}
}

func (r *legacyRing) applyUUIDDiff(added, removed [][16]byte) {
	if len(added) == 0 && len(removed) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range removed {
		r.removeUUIDLocked(id)
	}
	for _, id := range added {
		r.addUUIDLocked(id)
	}
}

// advance slides the active window to [now-120, now+120]. For normal small forward slides
// (typically +1 second per tick), HMAC-MD5 computation runs outside the write lock.
func (r *legacyRing) advance(now int64) {
	r.advanceIfOpen(now, nil)
}

func (r *legacyRing) advanceIfOpen(now int64, stopCh <-chan struct{}) {
	newStart := now - legacyAuthWindow
	newEnd := now + legacyAuthWindow

	r.tickMu.Lock()
	defer r.tickMu.Unlock()
	if stopCh != nil {
		select {
		case <-stopCh:
			return
		default:
		}
	}

	// Fast check + snapshot active UUIDs under RLock for small forward slides.
	r.mu.RLock()
	if r.hasWindow && r.winStart == newStart && r.winEnd == newEnd {
		r.mu.RUnlock()
		return
	}
	canOffLock := r.hasWindow &&
		newEnd > r.winEnd && newEnd-r.winEnd <= 5 &&
		newStart <= r.winEnd &&
		now-r.baseTS < (1<<28) && r.baseTS-now < (1<<28) &&
		len(r.uuidToIdx) > 0
	var preSecs []legacyPrecomputedSec
	var snapGen uint64
	var snapBase int64
	if canOffLock {
		snapGen = r.uuidGen
		snapBase = r.baseTS
		oldEnd := r.winEnd
		r.tickUUIDs = r.tickUUIDs[:0]
		for i := range r.uuids {
			if r.uuids[i].active {
				r.tickUUIDs = append(r.tickUUIDs, legacyActiveUUID{idx: uint32(i), uuid: r.uuids[i].uuid})
			}
		}
		r.mu.RUnlock()

		// Compute new seconds' HMAC-MD5 tags outside r.mu so lookups stay completely unblocked.
		totalNew := int(newEnd-oldEnd) * len(r.tickUUIDs)
		if cap(r.tickEntries) < totalNew {
			r.tickEntries = make([]legacyPrecomputedEntry, 0, totalNew)
		} else {
			r.tickEntries = r.tickEntries[:0]
		}
		var stamp [8]byte
		for ts := oldEnd + 1; ts <= newEnd; ts++ {
			binary.BigEndian.PutUint64(stamp[:], uint64(ts))
			tsOff := int32(ts - snapBase)
			start := len(r.tickEntries)
			for _, u := range r.tickUUIDs {
				tag := hmacMD5Stamp(u.uuid, stamp)
				k := binary.LittleEndian.Uint64(tag[:8])
				r.tickEntries = append(r.tickEntries, legacyPrecomputedEntry{
					k: k,
					v: legacySlotVal{uuidIdx: u.idx, tsOff: tsOff},
				})
			}
			preSecs = append(preSecs, legacyPrecomputedSec{
				ts:      ts,
				entries: r.tickEntries[start:],
			})
		}
	} else {
		r.mu.RUnlock()
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.ensureInitLocked()

	if !r.hasWindow || now-r.baseTS >= (1<<28) || r.baseTS-now >= (1<<28) || newStart > r.winEnd || newEnd < r.winStart {
		r.rebuildAllLocked(now)
		return
	}

	// Evict any bucket outside [newStart, newEnd].
	for i := range r.buckets {
		if r.buckets[i].valid && (r.buckets[i].ts < newStart || r.buckets[i].ts > newEnd) {
			r.evictBucketLocked(i)
		}
	}

	// Apply precomputed seconds if the active UUID set and baseTS did not change mid-flight.
	if len(preSecs) > 0 && r.uuidGen == snapGen && r.baseTS == snapBase {
		for _, ps := range preSecs {
			if ps.ts < newStart || ps.ts > newEnd {
				continue
			}
			slot := bucketSlot(ps.ts)
			b := &r.buckets[slot]
			if b.valid && b.ts == ps.ts {
				continue
			}
			if b.valid {
				r.evictBucketLocked(slot)
			}
			if cap(b.keys) < len(ps.entries) {
				b.keys = make([]uint64, 0, len(ps.entries))
			} else {
				b.keys = b.keys[:0]
			}
			for _, e := range ps.entries {
				r.insertEntryLocked(e.k, e.v)
				b.keys = append(b.keys, e.k)
			}
			b.ts = ps.ts
			b.valid = true
		}
	}

	// Populate any remaining missing seconds in [newStart, newEnd].
	for ts := newStart; ts <= newEnd; ts++ {
		slot := bucketSlot(ts)
		if !r.buckets[slot].valid || r.buckets[slot].ts != ts {
			r.populateSecondLocked(ts)
		}
	}
	r.winStart = newStart
	r.winEnd = newEnd
}

// lookup verifies authID in O(1), checks per-node membership in idx.VMessByUUID,
// and confirms the full 128-bit HMAC-MD5 digest outside the lock.
func (r *legacyRing) lookup(idx *UserIndex, authID [16]byte) (*VMessUserEntry, [8]byte, bool) {
	var stamp [8]byte
	if idx == nil || len(idx.VMessByUUID) == 0 {
		return nil, stamp, false
	}
	k := binary.LittleEndian.Uint64(authID[:8])

	type cand struct {
		uuid [16]byte
		ts   int64
	}
	var primary cand
	var hasPrimary bool
	var extras []cand

	r.mu.RLock()
	if r.index != nil {
		if val, ok := r.index[k]; ok {
			if int(val.uuidIdx) < len(r.uuids) && r.uuids[val.uuidIdx].active {
				primary = cand{uuid: r.uuids[val.uuidIdx].uuid, ts: r.baseTS + int64(val.tsOff)}
				hasPrimary = true
			}
			if ov := r.overflow[k]; len(ov) > 0 {
				extras = make([]cand, 0, len(ov))
				for _, e := range ov {
					if int(e.uuidIdx) < len(r.uuids) && r.uuids[e.uuidIdx].active {
						extras = append(extras, cand{uuid: r.uuids[e.uuidIdx].uuid, ts: r.baseTS + int64(e.tsOff)})
					}
				}
			}
		}
	}
	r.mu.RUnlock()

	if !hasPrimary && len(extras) == 0 {
		return nil, stamp, false
	}

	check := func(c cand) (*VMessUserEntry, [8]byte, bool) {
		uIdx, inNode := idx.VMessByUUID[c.uuid]
		if !inNode || uIdx < 0 || uIdx >= len(idx.VMessUsers) {
			return nil, stamp, false
		}
		var st [8]byte
		binary.BigEndian.PutUint64(st[:], uint64(c.ts))
		if hmacMD5Stamp(c.uuid, st) == authID {
			return &idx.VMessUsers[uIdx], st, true
		}
		return nil, stamp, false
	}

	if hasPrimary {
		if entry, st, ok := check(primary); ok {
			return entry, st, true
		}
	}
	for _, c := range extras {
		if entry, st, ok := check(c); ok {
			return entry, st, true
		}
	}
	return nil, stamp, false
}

func (r *legacyRing) windowBounds() (int64, int64, bool) {
	r.mu.RLock()
	ok := r.hasWindow
	ws, we := r.winStart, r.winEnd
	r.mu.RUnlock()
	return ws, we, ok
}

func (r *legacyRing) windowBoundsForUUID(uuid [16]byte) (int64, int64, bool) {
	r.mu.RLock()
	ok := r.hasWindow
	if ok {
		_, ok = r.uuidToIdx[uuid]
	}
	ws, we := r.winStart, r.winEnd
	r.mu.RUnlock()
	return ws, we, ok
}

type sharedLegacyNode struct {
	current   func() *UserIndex
	lastIdx   *UserIndex
	syncedIdx *atomic.Pointer[UserIndex]
	uuids     map[[16]byte]struct{}
}

// sharedLegacyManager maintains a single process-wide pointer-free legacyAuthRing
// shared across all VMess nodes in the process, deduplicating overlapping user UUIDs
// and running a single 1-second ticker goroutine instead of one per node.
type sharedLegacyManager struct {
	mu      sync.Mutex
	nextID  uint64
	nodes   map[uint64]*sharedLegacyNode
	ring    legacyRing
	stopCh  chan struct{}
	running bool
}

var globalLegacyAuth sharedLegacyManager

func diffIndexUUIDs(oldSet map[[16]byte]struct{}, idx *UserIndex) (added, removed [][16]byte) {
	if idx == nil || len(idx.VMessUsers) == 0 {
		if len(oldSet) == 0 {
			return nil, nil
		}
		removed = make([][16]byte, 0, len(oldSet))
		for id := range oldSet {
			removed = append(removed, id)
		}
		clear(oldSet)
		return nil, removed
	}
	for i := range idx.VMessUsers {
		id := idx.VMessUsers[i].User.UUIDBytes
		if _, ok := oldSet[id]; !ok {
			oldSet[id] = struct{}{}
			added = append(added, id)
		}
	}
	if len(idx.VMessByUUID) > 0 {
		if len(oldSet) > len(idx.VMessByUUID) {
			for id := range oldSet {
				if _, ok := idx.VMessByUUID[id]; !ok {
					delete(oldSet, id)
					removed = append(removed, id)
				}
			}
		}
	} else {
		curSet := make(map[[16]byte]struct{}, len(idx.VMessUsers))
		for i := range idx.VMessUsers {
			curSet[idx.VMessUsers[i].User.UUIDBytes] = struct{}{}
		}
		if len(oldSet) > len(curSet) {
			for id := range oldSet {
				if _, ok := curSet[id]; !ok {
					delete(oldSet, id)
					removed = append(removed, id)
				}
			}
		}
	}
	return added, removed
}

func (m *sharedLegacyManager) register(current func() *UserIndex) uint64 {
	return m.registerWithSync(current, nil)
}

func (m *sharedLegacyManager) registerWithSync(current func() *UserIndex, syncedIdx *atomic.Pointer[UserIndex]) uint64 {
	m.mu.Lock()
	if m.nodes == nil {
		m.nodes = make(map[uint64]*sharedLegacyNode)
	}
	m.nextID++
	id := m.nextID
	node := &sharedLegacyNode{
		current:   current,
		syncedIdx: syncedIdx,
		uuids:     make(map[[16]byte]struct{}),
	}
	m.nodes[id] = node

	var idx *UserIndex
	if current != nil {
		idx = current()
	}
	added, removed := diffIndexUUIDs(node.uuids, idx)
	node.lastIdx = idx
	m.ring.applyUUIDDiff(added, removed)
	if node.syncedIdx != nil {
		node.syncedIdx.Store(idx)
	}

	var startTickerCh chan struct{}
	if !m.running {
		m.ring.advance(time.Now().Unix())
		startTickerCh = make(chan struct{})
		m.stopCh = startTickerCh
		m.running = true
	}
	m.mu.Unlock()

	if startTickerCh != nil {
		go m.runTicker(startTickerCh)
	}
	return id
}

func (m *sharedLegacyManager) syncNode(id uint64, idx *UserIndex) {
	if id == 0 {
		return
	}
	m.mu.Lock()
	node := m.nodes[id]
	if node == nil || node.lastIdx == idx {
		m.mu.Unlock()
		return
	}
	added, removed := diffIndexUUIDs(node.uuids, idx)
	node.lastIdx = idx
	m.ring.applyUUIDDiff(added, removed)
	if node.syncedIdx != nil {
		node.syncedIdx.Store(idx)
	}
	m.mu.Unlock()
}

func (m *sharedLegacyManager) unregister(id uint64) {
	if id == 0 {
		return
	}
	m.mu.Lock()
	node := m.nodes[id]
	if node != nil {
		delete(m.nodes, id)
		if len(node.uuids) > 0 {
			removed := make([][16]byte, 0, len(node.uuids))
			for uid := range node.uuids {
				removed = append(removed, uid)
			}
			m.ring.applyUUIDDiff(nil, removed)
		}
	}
	if len(m.nodes) == 0 && m.running {
		close(m.stopCh)
		m.stopCh = nil
		m.running = false
		m.ring.reset()
	}
	m.mu.Unlock()
}

func (m *sharedLegacyManager) runTicker(stopCh chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			m.mu.Lock()
			if !m.running || m.stopCh != stopCh {
				m.mu.Unlock()
				return
			}
			for _, node := range m.nodes {
				if node.current == nil {
					continue
				}
				idx := node.current()
				if idx == node.lastIdx {
					continue
				}
				added, removed := diffIndexUUIDs(node.uuids, idx)
				node.lastIdx = idx
				m.ring.applyUUIDDiff(added, removed)
				if node.syncedIdx != nil {
					node.syncedIdx.Store(idx)
				}
			}
			m.mu.Unlock()
			m.ring.advanceIfOpen(time.Now().Unix(), stopCh)
		}
	}
}

// legacyAuthCache implements Soga-compatible `vmess auth mode: auto`: it accepts
// primary-UUID legacy MD5 AuthIDs for every VMess user, alongside AEAD.
// When started via start(), all Server instances share a single process-wide
// pointer-free ring while verifying per-node membership in O(1) against UserIndex.
type legacyAuthCache struct {
	mu        sync.Mutex
	started   atomic.Bool
	syncedIdx atomic.Pointer[UserIndex]
	nodeID    uint64
	current   func() *UserIndex

	// Standalone local ring used only when refresh() is invoked directly without start() (e.g. unit tests).
	local        *legacyRing
	localLastIdx atomic.Pointer[UserIndex]
	localUUIDs   map[[16]byte]struct{}
}

// refresh brings a standalone ring up to date for `idx` at time `now` (used by deterministic unit tests).
func (c *legacyAuthCache) refresh(idx *UserIndex, now int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.local == nil {
		c.local = &legacyRing{}
		c.localUUIDs = make(map[[16]byte]struct{})
	}
	if c.localLastIdx.Load() != idx {
		added, removed := diffIndexUUIDs(c.localUUIDs, idx)
		c.localLastIdx.Store(idx)
		c.local.applyUUIDDiff(added, removed)
	}
	if idx == nil {
		return
	}
	c.local.advance(now)
}

// sync incrementally updates this node's registered UUIDs in the shared cache when users change.
func (c *legacyAuthCache) sync(idx *UserIndex) {
	if !c.started.Load() {
		return
	}
	c.mu.Lock()
	id := c.nodeID
	c.mu.Unlock()
	if id != 0 {
		globalLegacyAuth.syncNode(id, idx)
	}
}

// lookupIn returns the matching user belonging to `idx` and the 8-byte timestamp used by the legacy header IV.
func (c *legacyAuthCache) lookupIn(idx *UserIndex, authID [16]byte) (*VMessUserEntry, [8]byte, bool) {
	if c.started.Load() {
		return globalLegacyAuth.ring.lookup(idx, authID)
	}
	c.mu.Lock()
	local := c.local
	c.mu.Unlock()
	if local == nil {
		return nil, [8]byte{}, false
	}
	return local.lookup(idx, authID)
}

// lookup returns the matching user and the 8-byte timestamp used by the legacy header IV.
func (c *legacyAuthCache) lookup(authID [16]byte) (*VMessUserEntry, [8]byte, bool) {
	if c.started.Load() {
		c.mu.Lock()
		curFn := c.current
		c.mu.Unlock()
		var idx *UserIndex
		if curFn != nil {
			idx = curFn()
		}
		return globalLegacyAuth.ring.lookup(idx, authID)
	}
	return c.lookupIn(c.localLastIdx.Load(), authID)
}

// syncedWindowBounds reports the currently indexed [winStart, winEnd] range when this cache
// is already synchronized with idx, allowing readLegacyVMessHeader to skip redundant n=0 scans.
func (c *legacyAuthCache) syncedWindowBounds(idx *UserIndex) (int64, int64, bool) {
	if c.started.Load() {
		if c.syncedIdx.Load() != idx {
			return 0, 0, false
		}
		return globalLegacyAuth.ring.windowBounds()
	}
	c.mu.Lock()
	local := c.local
	lastIdx := c.localLastIdx.Load()
	c.mu.Unlock()
	if local == nil || lastIdx != idx {
		return 0, 0, false
	}
	return local.windowBounds()
}

// windowBoundsForUUID reports the indexed [winStart, winEnd] range if uuid is present in the active ring.
func (c *legacyAuthCache) windowBoundsForUUID(idx *UserIndex, uuid [16]byte) (int64, int64, bool) {
	if c.started.Load() {
		return globalLegacyAuth.ring.windowBoundsForUUID(uuid)
	}
	c.mu.Lock()
	local := c.local
	lastIdx := c.localLastIdx.Load()
	c.mu.Unlock()
	if local == nil || lastIdx != idx {
		return 0, 0, false
	}
	return local.windowBoundsForUUID(uuid)
}

// start attaches this server to the process-wide shared legacy auth ring.
func (c *legacyAuthCache) start(current func() *UserIndex) {
	c.mu.Lock()
	if c.started.Load() {
		c.mu.Unlock()
		return
	}
	c.current = current
	c.nodeID = globalLegacyAuth.registerWithSync(current, &c.syncedIdx)
	c.started.Store(true)
	c.mu.Unlock()
}

func (c *legacyAuthCache) close() {
	c.mu.Lock()
	id := c.nodeID
	wasStarted := c.started.Swap(false)
	c.nodeID = 0
	c.current = nil
	c.syncedIdx.Store(nil)
	c.mu.Unlock()
	if wasStarted && id != 0 {
		globalLegacyAuth.unregister(id)
	}
}
