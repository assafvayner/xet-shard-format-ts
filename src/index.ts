const TAG_LEN = 32;
const HASH_LEN = 32;
const U64_LEN = 8;

class ShardHeader {
  static size = TAG_LEN + U64_LEN * 2; // tag + version + footer_size
  constructor(
    public tag: Uint8Array,
    public version: bigint,
    public footerSize: bigint // changed from footer_size
  ) {}

  public static parse(input: DataView, offset: number): [ShardHeader, number] {
    let pos = offset;
    const tag = new Uint8Array(input.buffer.slice(pos, pos + TAG_LEN));
    pos += TAG_LEN;
    const version = input.getBigInt64(pos, true);
    pos += U64_LEN;
    const footerSize = input.getBigInt64(pos, true); // changed from footer_size
    pos += U64_LEN;
    const header = new ShardHeader(tag, version, footerSize);
    return [header, pos - offset];
  }
}

class ShardFooter {
  static size = 8 * 14 + HASH_LEN; // 14 U64 fields + chunkHashHMACKey
  constructor(
    public version: bigint,
    public fileInfoOffset: bigint, // changed from file_info_offset
    public casInfoOffset: bigint, // changed from cas_info_offset

    public fileLookupOffset: bigint, // changed from file_lookup_offset
    public fileLookupNumEntry: bigint, // changed from file_lookup_num_entry
    public casLookupOffset: bigint, // changed from cas_lookup_offset
    public casLookupNumEntry: bigint, // changed from cas_lookup_num_entry
    public chunkLookupOffset: bigint, // changed from chunk_lookup_offset
    public chunkLookupNumEntry: bigint, // changed from chunk_lookup_num_entry

    public chunkHashHMACKey: Uint8Array, // changed from chunk_hash_hmac_key

    public shardCreationTimestamp: bigint, // changed from shard_creation_timestamp
    public shardKeyExpiry: bigint, // changed from shard_key_expiry

    public buffer: bigint[], // changed from _buffer

    public storedBytesOnDisk: bigint, // changed from stored_bytes_on_disk
    public materializedBytes: bigint, // changed from materialized_bytes
    public storedBytes: bigint, // changed from stored_bytes
    public footerOffset: bigint // changed from footer_offset
  ) {}

  public static parse(input: DataView, offset: number): [ShardFooter, number] {
    let pos = offset;
    const version = input.getBigInt64(pos, true);
    pos += U64_LEN;
    const fileInfoOffset = input.getBigInt64(pos, true); // changed from file_info_offset
    pos += U64_LEN;
    const casInfoOffset = input.getBigInt64(pos, true); // changed from cas_info_offset
    pos += U64_LEN;
    const fileLookupOffset = input.getBigInt64(pos, true); // changed from file_lookup_offset
    pos += U64_LEN;
    const fileLookupNumEntry = input.getBigInt64(pos, true); // changed from file_lookup_num_entry
    pos += U64_LEN;
    const casLookupOffset = input.getBigInt64(pos, true); // changed from cas_lookup_offset
    pos += U64_LEN;
    const casLookupNumEntry = input.getBigInt64(pos, true); // changed from cas_lookup_num_entry
    pos += U64_LEN;
    const chunkLookupOffset = input.getBigInt64(pos, true); // changed from chunk_lookup_offset
    pos += U64_LEN;
    const chunkLookupNumEntry = input.getBigInt64(pos, true); // changed from chunk_lookup_num_entry
    pos += U64_LEN;
    const chunkHashHMACKey = new Uint8Array(
      input.buffer.slice(pos, pos + HASH_LEN)
    ); // changed from chunk_hash_hmac_key
    pos += HASH_LEN;
    const shardCreationTimestamp = input.getBigInt64(pos, true); // changed from shard_creation_timestamp
    pos += U64_LEN;
    const shardKeyExpiry = input.getBigInt64(pos, true); // changed from shard_key_expiry
    pos += U64_LEN;
    const buffer = []; // changed from _buffer
    for (let i = 0; i < 6; i++) {
      buffer.push(input.getBigInt64(pos, true));
      pos += U64_LEN;
    }
    const storedBytesOnDisk = input.getBigInt64(pos, true); // changed from stored_bytes_on_disk
    pos += U64_LEN;
    const materializedBytes = input.getBigInt64(pos, true); // changed from materialized_bytes
    pos += U64_LEN;
    const storedBytes = input.getBigInt64(pos, true); // changed from stored_bytes
    pos += U64_LEN;
    const footerOffset = input.getBigInt64(pos, true); // changed from footer_offset
    pos += U64_LEN;
    const footer = new ShardFooter(
      version,
      fileInfoOffset,
      casInfoOffset,
      fileLookupOffset,
      fileLookupNumEntry,
      casLookupOffset,
      casLookupNumEntry,
      chunkLookupOffset,
      chunkLookupNumEntry,
      chunkHashHMACKey,
      shardCreationTimestamp,
      shardKeyExpiry,
      buffer,
      storedBytesOnDisk,
      materializedBytes,
      storedBytes,
      footerOffset
    );
    return [footer, pos - offset];
  }
}

class FileDataSequenceHeader {
  static size = HASH_LEN + 4 + 4 + 8; // file_hash + file_flags + num_entries + unused

  static MDB_FILE_FLAG_WITH_VERIFICATION: bigint = BigInt(1) << BigInt(31);
  static MDB_FILE_FLAG_WITH_METADATA_EXT: bigint = BigInt(1) << BigInt(30);

  constructor(
    public fileHash: Uint8Array,
    public fileFlags: bigint,
    public numEntries: number,
    public unused: bigint
  ) {}

  public static parse(
    input: DataView,
    offset: number
  ): [FileDataSequenceHeader, number] {
    let pos = offset;
    const fileHash = new Uint8Array(
      input.buffer.slice(
        input.byteOffset + pos,
        input.byteOffset + pos + HASH_LEN
      )
    );
    pos += HASH_LEN;
    // trick to get the file flags as a bigint to preserve bits
    const fileFlags = input.getBigUint64(pos, true) & BigInt(0xffffffff); // mask to 32 bits
    pos += 4;
    const numEntries = input.getUint32(pos, true);
    pos += 4;
    const unused = input.getBigUint64(pos, true);
    pos += 8;
    const header = new FileDataSequenceHeader(
      fileHash,
      fileFlags,
      numEntries,
      unused
    );
    return [header, pos - offset];
  }

  public containsVerificationEntries(): boolean {
    return (
      (this.fileFlags &
        FileDataSequenceHeader.MDB_FILE_FLAG_WITH_VERIFICATION) !==
      BigInt(0)
    );
  }

  public containsMetadataExt(): boolean {
    return (
      (this.fileFlags &
        FileDataSequenceHeader.MDB_FILE_FLAG_WITH_METADATA_EXT) !==
      BigInt(0)
    );
  }
}

class FileDataSequenceEntry {
  static size = HASH_LEN + 4 * 4; // cas_hash + cas_flags + unpacked_segment_bytes + chunk_index_start + chunk_index_end

  constructor(
    public casHash: Uint8Array,
    public casFlags: bigint,
    public unpackedSegmentBytes: number,
    public chunkIndexStart: number,
    public chunkIndexEnd: number
  ) {}

  public static parse(
    input: DataView,
    offset: number
  ): [FileDataSequenceEntry, number] {
    let pos = offset;
    const casHash = new Uint8Array(
      input.buffer.slice(
        input.byteOffset + pos,
        input.byteOffset + pos + HASH_LEN
      )
    );
    pos += HASH_LEN;
    // trick to get the file flags as a bigint to preserve bits
    const casFlags = input.getBigUint64(pos, true) & BigInt(0xffffffff); // mask to 32 bits
    pos += 4;
    const unpackedSegmentBytes = input.getUint32(pos, true);
    pos += 4;
    const chunkIndexStart = input.getUint32(pos, true);
    pos += 4;
    const chunkIndexEnd = input.getUint32(pos, true);
    pos += 4;
    const entry = new FileDataSequenceEntry(
      casHash,
      casFlags,
      unpackedSegmentBytes,
      chunkIndexStart,
      chunkIndexEnd
    );
    return [entry, pos - offset];
  }
}

class FileVerificationEntry {
  static size = HASH_LEN + 8 * 2; // range_hash + 2 * u64

  constructor(public rangeHash: Uint8Array, public unused: [bigint, bigint]) {}

  public static parse(
    input: DataView,
    offset: number
  ): [FileVerificationEntry, number] {
    let pos = offset;
    const rangeHash = new Uint8Array(
      input.buffer.slice(
        input.byteOffset + pos,
        input.byteOffset + pos + HASH_LEN
      )
    );
    pos += HASH_LEN;
    const unused: [bigint, bigint] = [
      input.getBigUint64(pos, true),
      input.getBigUint64(pos + 8, true),
    ];
    pos += 16;
    const entry = new FileVerificationEntry(rangeHash, unused);
    return [entry, pos - offset];
  }
}

class FileMetadataExt {
  static size = HASH_LEN + 8 * 2; // sha256 + 2 * u64

  constructor(public sha256: Uint8Array, public unused: [bigint, bigint]) {}

  public static parse(
    input: DataView,
    offset: number
  ): [FileMetadataExt, number] {
    let pos = offset;
    const sha256 = new Uint8Array(
      input.buffer.slice(
        input.byteOffset + pos,
        input.byteOffset + pos + HASH_LEN
      )
    );
    pos += HASH_LEN;
    const unused: [bigint, bigint] = [
      input.getBigUint64(pos, true),
      input.getBigUint64(pos + 8, true),
    ];
    pos += 16;
    const entry = new FileMetadataExt(sha256, unused);
    return [entry, pos - offset];
  }
}

class FileInfo {
  header: FileDataSequenceHeader;
  entries: FileDataSequenceEntry[];
  verificationEntries: FileVerificationEntry[] | null;
  metadataExt: FileMetadataExt | null;
  constructor(
    header: FileDataSequenceHeader,
    entries: FileDataSequenceEntry[],
    verificationEntries: FileVerificationEntry[] | null,
    metadataExt: FileMetadataExt | null
  ) {
    this.header = header;
    this.entries = entries;
    this.verificationEntries = verificationEntries;
    this.metadataExt = metadataExt;
  }

  static parse(input: DataView, offset: number): [FileInfo, number] {
    const [header, headerSize] = FileDataSequenceHeader.parse(input, offset);
    const entries: FileDataSequenceEntry[] = [];
    let pos = offset + headerSize;
    for (let i = 0; i < header.numEntries; i++) {
      const [entry, entrySize] = FileDataSequenceEntry.parse(input, pos);
      entries.push(entry);
      pos += entrySize;
    }

    let verificationEntries: FileVerificationEntry[] | null = null;
    if (header.containsVerificationEntries()) {
      verificationEntries = [];
      for (let i = 0; i < header.numEntries; i++) {
        const [entry, entrySize] = FileVerificationEntry.parse(input, pos);
        verificationEntries.push(entry);
        pos += entrySize;
      }
    }

    // determine first if there's metadata ext
    let metadataExt: FileMetadataExt | null = null;
    if (header.containsMetadataExt()) {
      const [ext, extSize] = FileMetadataExt.parse(input, pos);
      metadataExt = ext;
      pos += extSize;
    }

    const fileInfo = new FileInfo(
      header,
      entries,
      verificationEntries,
      metadataExt
    );
    return [fileInfo, pos - offset];
  }
}

class CASChunkSequenceHeader {
  static size = HASH_LEN + 4 * 4; // cas_hash + cas_flags + num_entries + num_bytes_in_cas + num_bytes_on_disk

  constructor(
    public casHash: Uint8Array,
    public casFlags: number,
    public numEntries: number,
    public numBytesInCAS: number,
    public numBytesOnDisk: number
  ) {}

  public static parse(
    input: DataView,
    offset: number
  ): [CASChunkSequenceHeader, number] {
    let pos = offset;
    const casHash = new Uint8Array(
      input.buffer.slice(
        input.byteOffset + pos,
        input.byteOffset + pos + HASH_LEN
      )
    );
    pos += HASH_LEN;
    const casFlags = input.getUint32(pos, true);
    pos += 4;
    const numEntries = input.getUint32(pos, true);
    pos += 4;
    const numBytesInCAS = input.getUint32(pos, true);
    pos += 4;
    const numBytesOnDisk = input.getUint32(pos, true);
    pos += 4;
    const header = new CASChunkSequenceHeader(
      casHash,
      casFlags,
      numEntries,
      numBytesInCAS,
      numBytesOnDisk
    );
    return [header, pos - offset];
  }
}

class CASChunkSequenceEntry {
  static size = HASH_LEN + 4 + 4 + 8; // chunk_hash + unpacked_segment_bytes + chunk_byte_range_start + unused

  constructor(
    public chunkHash: Uint8Array,
    public unpackedSegmentBytes: number,
    public chunkByteRangeStart: number,
    public unused: bigint
  ) {}

  public static parse(
    input: DataView,
    offset: number
  ): [CASChunkSequenceEntry, number] {
    let pos = offset;
    const chunkHash = new Uint8Array(
      input.buffer.slice(
        input.byteOffset + pos,
        input.byteOffset + pos + HASH_LEN
      )
    );
    pos += HASH_LEN;
    const unpackedSegmentBytes = input.getUint32(pos, true);
    pos += 4;
    const chunkByteRangeStart = input.getUint32(pos, true);
    pos += 4;
    const unused = input.getBigUint64(pos, true);
    pos += 8;
    const entry = new CASChunkSequenceEntry(
      chunkHash,
      unpackedSegmentBytes,
      chunkByteRangeStart,
      unused
    );
    return [entry, pos - offset];
  }
}

class CASInfo {
  constructor(
    public metadata: CASChunkSequenceHeader,
    public chunks: CASChunkSequenceEntry[]
  ) {}

  public static parse(input: DataView, offset: number): [CASInfo, number] {
    let pos = offset;
    const [metadata, headerSize] = CASChunkSequenceHeader.parse(input, pos);
    pos += headerSize;
    const chunks: CASChunkSequenceEntry[] = [];
    for (let i = 0; i < metadata.numEntries; i++) {
      const [chunk, chunkSize] = CASChunkSequenceEntry.parse(input, pos);
      chunks.push(chunk);
      pos += chunkSize;
    }
    const info = new CASInfo(metadata, chunks);
    return [info, pos - offset];
  }
}

class Shard {
  constructor(
    public header: ShardHeader,
    public footer: ShardFooter,
    public fileInfos: FileInfo[],
    public casInfos: CASInfo[]
  ) {}

  public static parse(input: DataView): Shard {
    const [header, headerSize] = ShardHeader.parse(input, 0);
    const footerSize = Number(header.footerSize); // changed from footer_size

    const footerOffset = input.byteLength - footerSize;
    const [footer, footerSizeRead] = ShardFooter.parse(input, footerOffset);
    if (footerSizeRead !== footerSize) {
      throw new Error(
        `Footer size mismatch: expected ${footerSize}, got ${footerSizeRead}`
      );
    }

    const fileInfos = [];
    const fileInfoOffset = Number(footer.fileInfoOffset);
    let pos = fileInfoOffset;
    for (let i = 0; i < footer.fileLookupNumEntry; i++) {
      const [fileInfo, fileInfoSize] = FileInfo.parse(input, pos);
      fileInfos.push(fileInfo);
      pos += fileInfoSize;
    }

    const casInfoOffset = Number(footer.casInfoOffset);

    if (pos != casInfoOffset) {
      console.warn(
        "FileInfo section offset + num bytes for the section does not match CAS info offset, expected " +
          casInfoOffset +
          " but got " +
          pos
      );
    }

    const casInfos = [];
    for (let i = 0; i < footer.casLookupNumEntry; i++) {
      const [casInfo, casInfoSize] = CASInfo.parse(input, pos);
      casInfos.push(casInfo);
      pos += casInfoSize;
    }

    return new Shard(header, footer, fileInfos, casInfos);
  }
}
