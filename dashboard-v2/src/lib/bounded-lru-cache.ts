export interface BoundedLruCache<K, V> {
  get(key: K): V | undefined;
  set(key: K, value: V): void;
  has(key: K): boolean;
  size(): number;
  clear(): void;
}

export interface BoundedLruCacheOptions {
  maxEntries: number;
}

/**
 * Creates a deterministic, access-ordered cache with a hard entry-count bound.
 * A zero capacity is valid and turns the cache into a no-op; invalid capacities
 * fail closed at construction so the configured bound cannot be ambiguous.
 */
export function createBoundedLruCache<K, V>({ maxEntries }: BoundedLruCacheOptions): BoundedLruCache<K, V> {
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 0) {
    throw new RangeError("Bounded LRU cache capacity must be a non-negative safe integer");
  }

  const entries = new Map<K, V>();

  return {
    get(key) {
      if (!entries.has(key)) return undefined;
      const value = entries.get(key)!;
      entries.delete(key);
      entries.set(key, value);
      return value;
    },

    set(key, value) {
      if (maxEntries === 0) return;
      entries.delete(key);
      entries.set(key, value);
      while (entries.size > maxEntries) {
        const oldest = entries.keys().next();
        if (oldest.done) break;
        entries.delete(oldest.value);
      }
    },

    has(key) {
      return entries.has(key);
    },

    size() {
      return entries.size;
    },

    clear() {
      entries.clear();
    },
  };
}
