const ENC = new TextEncoder();

export type MsgPackValue =
  | number
  | bigint
  | Uint8Array
  | string
  | MsgPackValue[]
  | { __raw__: Uint8Array };

export const raw = (bytes: Uint8Array): MsgPackValue => ({ __raw__: bytes });

export class MpWriter {
  #buf: number[] = [];

  buffer(): Uint8Array {
    return Uint8Array.from(this.#buf);
  }

  private byte(c: number): void {
    this.#buf.push(c & 0xff);
  }

  private bytes(b: Uint8Array): void {
    for (const v of b) this.#buf.push(v);
  }

  arr(size: number): this {
    if (size < 16) this.byte(0x90 | size);
    else if (size < 0x10000) {
      this.byte(0xdc);
      this.byte(size >> 8);
      this.byte(size);
    } else {
      this.byte(0xdd);
      this.#buf.push((size >>> 24) & 0xff, (size >>> 16) & 0xff, (size >>> 8) & 0xff, size & 0xff);
    }
    return this;
  }

  fixUint(v: number): this {
    if (v >= 0x80) throw new Error("sbc/msgpack: value out of fixint range");
    this.byte(v);
    return this;
  }

  uint32(v: number): this {
    this.byte(0xce);
    this.bytes(Uint8Array.from([(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]));
    return this;
  }

  uint64(v: number | bigint): this {
    const big = BigInt(v);
    if (big < 0 || big >= 1n << 64n) throw new Error("sbc/msgpack: u64 out of range");
    this.byte(0xcf);
    for (let shift = 56n; shift >= 0n; shift -= 8n) this.byte(Number((big >> shift) & 0xffn));
    return this;
  }

  bin(b: Uint8Array): this {
    const size = b.length;
    if (size < 0x100 - 1) {
      this.byte(0xc4);
      this.byte(size);
    } else if (size < 0x10000 - 1) {
      this.byte(0xc5);
      this.byte(size >> 8);
      this.byte(size);
    } else {
      this.byte(0xc6);
      this.bytes(
        Uint8Array.from([
          (size >>> 24) & 0xff,
          (size >>> 16) & 0xff,
          (size >>> 8) & 0xff,
          size & 0xff,
        ]),
      );
    }
    this.bytes(b);
    return this;
  }

  str(s: string): this {
    const b = ENC.encode(s);
    if (b.length > 31) throw new Error("sbc/msgpack: str too long");
    this.byte(0xa0 | b.length);
    this.bytes(b);
    return this;
  }

  direct(b: Uint8Array): this {
    this.bytes(b);
    return this;
  }

  write(v: MsgPackValue): this {
    if (Array.isArray(v)) {
      this.arr(v.length);
      for (const item of v) this.write(item);
    } else if (typeof v === "number" || typeof v === "bigint") {
      this.uint64(v);
    } else if (v instanceof Uint8Array) {
      this.bin(v);
    } else if (typeof v === "string") {
      this.str(v);
    } else if (v && typeof v === "object" && "__raw__" in v) {
      this.direct((v as { __raw__: Uint8Array }).__raw__);
    } else {
      throw new Error("sbc/msgpack: unsupported value");
    }
    return this;
  }
}

export class MpReader {
  #i = 0;
  constructor(private readonly b: Uint8Array) {}

  pos(): number {
    return this.#i;
  }

  private u8(): number {
    if (this.#i >= this.b.length) throw new Error("sbc/msgpack: unexpected end");
    const v = this.b[this.#i++];
    if (v === undefined) throw new Error("sbc/msgpack: unexpected end");
    return v;
  }

  private take(n: number): Uint8Array {
    const end = this.#i + n;
    if (end > this.b.length) throw new Error("sbc/msgpack: unexpected end");
    const slice = this.b.subarray(this.#i, end);
    this.#i = end;
    return slice;
  }

  arraySize(): number {
    const c = this.u8();
    if ((c & 0xf0) === 0x90) return c & 0x0f;
    if (c === 0xdc) return (this.u8() << 8) | this.u8();
    if (c === 0xdd) return (this.u8() << 24) | (this.u8() << 16) | (this.u8() << 8) | this.u8();
    throw new Error("sbc/msgpack: expected array");
  }

  uint(): number {
    const c = this.u8();
    if (c < 0x80) return c;
    if (c === 0xcc) return this.u8();
    throw new Error("sbc/msgpack: expected uint");
  }

  u32(): number {
    const c = this.u8();
    if (c !== 0xce) throw new Error("sbc/msgpack: expected u32");
    return ((this.u8() << 24) | (this.u8() << 16) | (this.u8() << 8) | this.u8()) >>> 0;
  }

  i32(): number {
    return this.u32() | 0;
  }

  u64(): bigint {
    const c = this.u8();
    if (c !== 0xcf) throw new Error("sbc/msgpack: expected u64");
    let v = 0n;
    for (let k = 0; k < 8; k++) v = (v << 8n) | BigInt(this.u8());
    return v;
  }

  number64(): number {
    return Number(this.u64());
  }

  bin(): Uint8Array {
    const c = this.u8();
    let size: number;
    if (c === 0xc4) size = this.u8();
    else if (c === 0xc5) size = (this.u8() << 8) | this.u8();
    else if (c === 0xc6)
      size = (this.u8() << 24) | (this.u8() << 16) | (this.u8() << 8) | this.u8();
    else throw new Error("sbc/msgpack: expected binary");
    return this.take(size);
  }

  str(): string {
    const c = this.u8();
    if (((c >> 5) & 0x07) !== 5) throw new Error("sbc/msgpack: expected string");
    const size = c & 0x1f;
    return new TextDecoder().decode(this.take(size));
  }
}
