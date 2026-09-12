import { assertEquals, assertThrows } from "@vyline/protocol/stack/assert";
import * as schema from "./schema.ts";
import {
  CC_MSG,
  decodeCcConnReq,
  decodeCcConnRsp,
  decodeCcInfoReq,
  decodeCcInfoRsp,
  decodeCcParticipateRsp,
  decodeCcRelReq,
  decodeCcSetupRsp,
  decodeCcVerifyRsp,
  decodeFields,
  decodeMcDataReq,
  decodeMcDataRsp,
  decodeNativeSetupOffer,
  decodePlanetMsg,
  decodeVarint,
  encodeVarint,
  MC_MSG,
  packCcConnReq,
  packCcConnRsp,
  packCcInfoReq,
  packCcInfoRsp,
  packCcParticipateReq,
  packCcRelReq,
  packCcSetupReq,
  packCcSetupRsp,
  packCcVerifyReq,
  packCcVerifyRsp,
  packKeepaliveReq,
  packMcDataReq,
  packMcDataRsp,
  packMcDataSessionPayload,
  packMcStreamControl,
  decodeMcStreamControl,
  packNativeGroupParticipateOffer,
  packNativeSetupOffer,
  packPlanetCcHdr,
  packPlanetCcMsg,
  packPlanetFeatureRegister,
  packPlanetMcMsg,
  packPlanetMsg,
  packPlanetMsgHdr,
  packPlanetScMsgKaReq,
  packPlanetUeInfo,
  packPlanetUserAgent,
  packStrmSpec,
  WireType,
  wrapCcMsg,
  wrapMcMsg,
} from "./schema.ts";

Deno.test("group stream subscription uses explicit channel and native notification fields", () => {
  const packed = schema.packMcStrmReq(9, [{ ssrc: 31, channel: 42, start: true }]);
  const outer = decodeFields(packed);
  assertEquals(outer.find((f) => f.tag === 2)?.value, 9n);
  const fields = decodeFields(outer.find((f) => f.tag === 1)!.value as Uint8Array);
  assertEquals(
    fields.filter((f) => f.wireType === 0).map((f) => [f.tag, f.value]),
    [
      [1, 1n],
      [3, 31n],
      [5, 1n],
      [6, 1n],
      [7, 42n],
    ],
  );
  assertEquals(
    fields.some((f) => f.tag === 2),
    false,
  ); // Native omits uid in STRM_REQ.
  assertEquals(
    decodeFields(fields.find((f) => f.tag === 8)!.value as Uint8Array).map((f) => [f.tag, f.value]),
    [
      [1, 2n],
      [2, 0n],
    ],
  );
  assertThrows(() => schema.packMcStrmReq(1, [{ ssrc: -1, channel: 0, start: true }]));
  assertThrows(() =>
    schema.packMcStrmReq(1, [{ ssrc: 1, channel: undefined as unknown as number, start: true }]),
  );
  assertEquals(schema.decodeMcNotifyStrmReq(new Uint8Array([10, 6, 8, 1, 24, 31, 40, 42])), [
    { state: 1, ssrc: 31, channel: 42, mid: undefined },
  ]);
  for (const body of [
    [10, 4, 8, 1, 24, 31],
    [10, 6, 8, 3, 24, 31, 40, 42],
    [10, 8, 8, 1, 8, 2, 24, 31, 40, 42],
  ])
    assertThrows(() => schema.decodeMcNotifyStrmReq(new Uint8Array(body)));
});

Deno.test("group publisher decodes SVC layer requests without assuming an optional channel", () => {
  const body = new Uint8Array([
    10, 18, 8, 1, 24, 111, 40, 0, 48, 1, 66, 4, 8, 2, 16, 1, 74, 2, 65, 66, 16, 3,
  ]);
  const parsed = schema.decodeMcStrmReq(body);
  assertEquals(parsed.sequence, 3);
  assertEquals(parsed.requests, [
    {
      type: 1,
      ssrc: 111,
      startOperation: 0,
      encoding: 1,
      layers: [{ layer: 2, codec: 1 }],
      mid: undefined,
      channel: undefined,
    },
  ]);
  assertThrows(() => schema.decodeMcStrmReq(new Uint8Array([10, 2, 8, 1])));
  assertThrows(() => schema.decodeMcStrmReq(new Uint8Array([10, 6, 8, 1, 8, 0, 24, 111])));
});

Deno.test("conference/control protobuf rejects truncated and overflowing fields", () => {
  for (const bytes of [[], [0x80], new Array(11).fill(0x80), [...new Array(9).fill(0xff), 2]]) {
    assertThrows(() => decodeVarint(new Uint8Array(bytes), 0));
  }
  for (const bytes of [[0, 0], [0x0a, 2, 1], [0x0a, 0x80], [0x0d, 1, 2, 3], [0x09, 1], [0x08]]) {
    assertThrows(() => decodeFields(new Uint8Array(bytes)));
  }
  assertEquals(decodeVarint(new Uint8Array([...new Array(9).fill(0xff), 1]), 0), [
    (1n << 64n) - 1n,
    10,
  ]);
  assertThrows(() => decodeFields(Uint8Array.from({ length: 8194 }, (_, i) => (i % 2 ? 0 : 8))));
});

Deno.test("VP8 normal-video offer preserves audio and marks initial video separately", () => {
  const material = {
    mediaPubKey: new Uint8Array(33),
    mediaKeyId: 1,
    mediaNonce: new Uint8Array(16),
    mediaSecret: new Uint8Array(30),
  };
  for (const enabled of [false, true]) {
    const offer = decodeNativeSetupOffer(packNativeSetupOffer(material, "simple", { enabled }));
    assertEquals(
      offer.media.map((m) => [m.name, m.enabled, m.kinds]),
      [
        ["A", 1, [1]],
        ["V", Number(enabled), [2]],
        ["D", 1, [6]],
      ],
    );
    assertEquals(offer.media.find((m) => m.name === "V")?.rtpPort, 111);
    assertEquals(offer.mediaPubKey, undefined);
  }
});

Deno.test("MCMMD video START uses native big-endian control layout and rejects truncation", () => {
  const data = packMcStreamControl({ operation: 1, ssrcs: [111, 211], mediaKind: 2, code: 0 });
  assertEquals(
    data,
    new Uint8Array([
      0, 1, 0, 0, 0, 20, 0, 0, 0, 1, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 111, 0, 0, 0, 211,
    ]),
  );
  assertEquals(decodeMcStreamControl(data), {
    operation: 1,
    ssrcs: [111, 211],
    mediaKind: 2,
    code: 0,
  });
  assertEquals(decodeMcStreamControl(packMcDataSessionPayload(new Uint8Array([1]))), undefined);
  for (let i = 0; i < data.length; i++) assertThrows(() => decodeMcStreamControl(data.slice(0, i)));
  const badCount = data.slice();
  badCount[11] = 3;
  assertThrows(() => decodeMcStreamControl(badCount));
});

Deno.test("MCMMD ignores optional sender overruns like native without weakening control bounds", () => {
  const packet = new Uint8Array([
    0,
    1,
    0,
    0,
    0,
    22,
    0,
    0, // 22-byte body, padded to 24 bytes.
    0,
    1,
    0,
    1,
    0,
    0,
    0,
    2,
    0,
    0,
    0,
    0,
    0x11,
    0x11,
    0x11,
    0x11,
    0,
    6,
    0,
    0,
    0,
    0,
    0,
    0, // Sender claims 6, only 4 logical bytes remain.
  ]);
  assertEquals(decodeMcStreamControl(packet), {
    operation: 1,
    mediaKind: 2,
    code: 0,
    ssrcs: [0x11111111],
  });
  const truncated = packet.slice();
  truncated[11] = 3;
  assertThrows(() => decodeMcStreamControl(truncated));
  assertThrows(() => decodeMcStreamControl(packet.subarray(0, 30)));
});

Deno.test("packPlanetMsgHdr matches an observed 96-byte header shape", () => {
  // Reproduce an observed msg_pack header shape without account-specific
  // identifiers.
  const expected = new Uint8Array([
    // field 1 (user_id, 33B str)
    0x0a,
    0x21,
    ...new TextEncoder().encode("u00000000000000000000000000000000"),
    // field 2 (msg_id varint = 4353)
    0x10,
    0x81,
    0x22,
    // field 3 (sess_id 16B)
    0x1a,
    0x10,
    0xb0,
    0xc2,
    0xa7,
    0x4c,
    0xe7,
    0xcd,
    0x45,
    0x02,
    0xa0,
    0xfa,
    0x32,
    0x58,
    0x6d,
    0xa9,
    0x0e,
    0x54,
    // field 4 (tran_id 16B)
    0x22,
    0x10,
    0xfc,
    0x4e,
    0xd0,
    0x77,
    0xd5,
    0xe2,
    0x41,
    0x75,
    0xab,
    0x59,
    0x6e,
    0xda,
    0x73,
    0x51,
    0xcb,
    0xe3,
    // field 5 (tran_seq varint = 797128754)
    0x28,
    0xb2,
    0xf0,
    0x8c,
    0xfc,
    0x02,
    // field 6 (loc_nonce varint = 290579788)
    0x30,
    0xcc,
    0xca,
    0xc7,
    0x8a,
    0x01,
    // field 7 (rmt_nonce varint = 7642030284661133203)
    0x38,
    0x93,
    0x9f,
    0x84,
    0x80,
    0xe0,
    0xc1,
    0xfc,
    0x86,
    0x6a,
  ]);
  const got = packPlanetMsgHdr({
    userId: "u00000000000000000000000000000000",
    msgId: 4353,
    sessId: expected.subarray(40, 56),
    tranId: expected.subarray(58, 74),
    tranSeq: 797128754,
    locNonce: 290579788n,
    rmtNonce: 7642030284661133203n,
  });
  assertEquals(got, expected);
});

Deno.test("decodeFields parses the captured header into the expected fields", () => {
  const captured = new Uint8Array([
    0x0a,
    0x21,
    ...new TextEncoder().encode("u00000000000000000000000000000000"),
    0x10,
    0x81,
    0x22,
    0x1a,
    0x10,
    0xb0,
    0xc2,
    0xa7,
    0x4c,
    0xe7,
    0xcd,
    0x45,
    0x02,
    0xa0,
    0xfa,
    0x32,
    0x58,
    0x6d,
    0xa9,
    0x0e,
    0x54,
    0x22,
    0x10,
    0xfc,
    0x4e,
    0xd0,
    0x77,
    0xd5,
    0xe2,
    0x41,
    0x75,
    0xab,
    0x59,
    0x6e,
    0xda,
    0x73,
    0x51,
    0xcb,
    0xe3,
    0x28,
    0xb2,
    0xf0,
    0x8c,
    0xfc,
    0x02,
    0x30,
    0xcc,
    0xca,
    0xc7,
    0x8a,
    0x01,
    0x38,
    0x93,
    0x9f,
    0x84,
    0x80,
    0xe0,
    0xc1,
    0xfc,
    0x86,
    0x6a,
  ]);
  const f = decodeFields(captured);
  assertEquals(f.length, 7);
  assertEquals(
    new TextDecoder().decode(f[0].value as Uint8Array),
    "u00000000000000000000000000000000",
  );
  assertEquals(f[1].value, 4353n);
  assertEquals((f[2].value as Uint8Array).length, 16);
  assertEquals((f[3].value as Uint8Array).length, 16);
  assertEquals(f[4].value, 797128754n);
  assertEquals(f[5].value, 290579788n);
  assertEquals(f[6].value, 7642030284661133203n);
});

Deno.test("packCcSetupReq emits initiator + responder + svc_key in tag order", () => {
  const wire = packCcSetupReq({
    initiator: "uA",
    responder: "uB",
    svcKey: "BASE64PUBKEY==",
    credential: new Uint8Array([1, 2, 3]),
  });
  const fields = decodeFields(wire);
  const byTag = new Map(fields.map((f) => [f.tag, f]));
  assertEquals(new TextDecoder().decode(byTag.get(1)!.value as Uint8Array), "uA");
  assertEquals(new TextDecoder().decode(byTag.get(2)!.value as Uint8Array), "uB");
  assertEquals(new TextDecoder().decode(byTag.get(12)!.value as Uint8Array), "BASE64PUBKEY==");
  assertEquals(byTag.get(10)!.value, new Uint8Array([1, 2, 3]));
});

Deno.test("packCcSetupRsp round-trips setup response fields", () => {
  const wire = packCcSetupRsp({
    result: 0,
    aliveRptInterval: 5,
    noAnsToSec: 30,
    svcId: "svc",
    tgtSvcId: "target",
    interDomain: true,
  });
  const decoded = decodeCcSetupRsp(wire);
  assertEquals(decoded.result, 0);
  assertEquals(decoded.aliveRptInterval, 5);
  assertEquals(decoded.noAnsToSec, 30);
  assertEquals(decoded.svcId, "svc");
  assertEquals(decoded.tgtSvcId, "target");
  assertEquals(decoded.interDomain, true);
});

Deno.test("packNativeGroupParticipateOffer emits group media records", () => {
  const offer = packNativeGroupParticipateOffer({
    mediaSecret: new Uint8Array(30).fill(7),
  });
  assertEquals(offer.length, 265);
  const decoded = decodeNativeSetupOffer(offer);
  assertEquals(
    decoded.media.map((m) => m.name),
    ["A", "V", "D"],
  );
  assertEquals(
    decoded.media.map((m) => m.kind),
    [1, 7, 6],
  );
  assertEquals(
    decoded.media.map((m) => m.enabled),
    [1, 0, 1],
  );
  assertEquals(
    decoded.media.map((m) => m.rtpPort),
    [103, 113, 123],
  );
  assertEquals(
    decoded.media.map((m) => m.rtcpId),
    [203, 213, 223],
  );
  assertEquals(decoded.mediaSecret, new Uint8Array(30).fill(7));
  assertEquals(decoded.media.find((m) => m.name === "V")?.features, [
    { id: 0, version: 2 },
    { id: 2, version: 1 },
  ]);
  assertEquals(decoded.mediaPubKey, undefined);
  assertEquals(decoded.version, { major: 0, mode: 3 });
});

Deno.test("packCcParticipateReq emits native group join field order", () => {
  const wire = packCcParticipateReq({
    participant: "u00000000000000000000000000000000",
    roomId: "c00000000000000000000000000000000",
    pZone: "jp",
    xZone: "jp",
    orionIp: "10.0.0.1",
    mixIp: "10.0.0.2",
    ua: packPlanetUserAgent({
      osName: "Android",
      osVersion: "36",
      deviceName: "Pixel 6a",
    }),
    devId: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    commTypeFlags: 1,
    capas: [1, 2, 3, 6, 4, 5],
    offer: new Uint8Array([1, 2, 3]),
    credential: new Uint8Array(32).fill(1),
    svcKey: "groupcall.audio",
    netType: 1,
    mChanId: 0x7d3158f8n,
    mixPort: 33828,
    features: [packPlanetFeatureRegister(16, true, 0), packPlanetFeatureRegister(17, false, 0)],
    roomAttrs: [1],
    recvRtp: 2,
    maxChanCnt: 30,
    unavailToSec: 0,
    pdtpOndemandStreams: [new Uint8Array([0x08, 0x04, 0x10, 0x02])],
    ueExtraInfo: new Uint8Array([0x08, 0x01]),
    pathCheck: false,
  });
  const fields = decodeFields(wire);
  assertEquals(
    fields.map((f) => f.tag),
    [
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 10, 10, 10, 10, 10, 11, 12, 13, 14, 15, 17, 18, 18, 19, 20, 22,
      23, 24, 53, 102,
    ],
  );
  assertEquals(
    new TextDecoder().decode(fields.find((f) => f.tag === 13)!.value as Uint8Array),
    "groupcall.audio",
  );
});

Deno.test("decodeCcParticipateRsp and decodeCcRelReq parse group replies", () => {
  const rsp = decodeCcParticipateRsp(new Uint8Array([0x08, 0x00, 0x32, 0x03, 1, 2, 3, 0x40, 0x01]));
  assertEquals(rsp.result, 0);
  assertEquals(rsp.answer, new Uint8Array([1, 2, 3]));
  assertEquals(rsp.contentsType, 1);

  const rel = decodeCcRelReq(
    packCcRelReq({
      relCode: 219,
      relPhrase: "closed",
      releaser: "participant",
      commMediaFlags: 1,
    }),
  );
  assertEquals(rel.relCode, 219);
  assertEquals(rel.relPhrase, "closed");
  assertEquals(rel.releaser, "participant");
  assertEquals(rel.commMediaFlags, 1);
});

Deno.test("packStrmSpec matches native group mc_data_req payload", () => {
  const base = 0xe3530100;
  const state = { paused: false, code: 0 };
  const spec = packStrmSpec({
    strms: [
      {
        ssrc: base + 0x79,
        bitrate: { target: 32 },
        state,
        ptime: 40,
        retx: { periOn: true, periIntvMs: 40, periLossThre: [0, 0, 20] },
        fecLossThre: [],
      },
      {
        ssrc: base + 0xd9,
        bitrate: { min: 100, max: 1200, target: 800 },
        state,
        retx: { periOn: false },
        fecLossThre: [0, 1, 10],
      },
      {
        ssrc: base + 0xa9,
        bitrate: { max: 2000 },
        state,
        retx: { periOn: false },
        fecLossThre: [],
      },
    ],
    fbIntv: 200,
    tp: 1,
    fbOn: true,
    txStrms: [
      {
        ssrc: base + 0x7d,
        state,
        retx: { reqdOn: true, reqdRttThre: 300 },
      },
      {
        ssrc: base + 0xdd,
        state,
        retx: { reqdOn: false },
      },
    ],
    link: {
      bwInitKbps: 1200,
      bwMaxKbps: 3000,
      probeRate: 0.2,
      probeBrMaxKbps: 200,
    },
  });
  assertEquals(
    spec,
    new Uint8Array([
      0x0a, 0x20, 0x08, 0xf9, 0x82, 0xcc, 0x9a, 0x0e, 0x12, 0x02, 0x18, 0x20, 0x1a, 0x04, 0x08,
      0x00, 0x10, 0x00, 0x28, 0x28, 0x32, 0x0a, 0x08, 0x01, 0x10, 0x28, 0x18, 0x00, 0x18, 0x00,
      0x18, 0x14, 0x3a, 0x00, 0x0a, 0x22, 0x08, 0xd9, 0x83, 0xcc, 0x9a, 0x0e, 0x12, 0x08, 0x08,
      0x64, 0x10, 0xb0, 0x09, 0x18, 0xa0, 0x06, 0x1a, 0x04, 0x08, 0x00, 0x10, 0x00, 0x32, 0x02,
      0x08, 0x00, 0x3a, 0x06, 0x08, 0x00, 0x08, 0x01, 0x08, 0x0a, 0x0a, 0x17, 0x08, 0xa9, 0x83,
      0xcc, 0x9a, 0x0e, 0x12, 0x03, 0x10, 0xd0, 0x0f, 0x1a, 0x04, 0x08, 0x00, 0x10, 0x00, 0x32,
      0x02, 0x08, 0x00, 0x3a, 0x00, 0x10, 0xc8, 0x01, 0x18, 0x01, 0x28, 0x01, 0x32, 0x13, 0x08,
      0xfd, 0x82, 0xcc, 0x9a, 0x0e, 0x12, 0x04, 0x08, 0x00, 0x10, 0x00, 0x1a, 0x05, 0x08, 0x01,
      0x10, 0xac, 0x02, 0x32, 0x10, 0x08, 0xdd, 0x83, 0xcc, 0x9a, 0x0e, 0x12, 0x04, 0x08, 0x00,
      0x10, 0x00, 0x1a, 0x02, 0x08, 0x00, 0x3a, 0x0e, 0x08, 0xb0, 0x09, 0x10, 0xb8, 0x17, 0x1d,
      0xcd, 0xcc, 0x4c, 0x3e, 0x20, 0xc8, 0x01,
    ]),
  );

  const data = packMcDataSessionPayload(spec);
  assertEquals(data.length, 168);
  assertEquals(
    data.subarray(0, 8),
    new Uint8Array([0x00, 0x02, 0x00, 0x00, 0x00, 0x9d, 0x00, 0x00]),
  );
  assertEquals(data.subarray(8, 8 + spec.length), spec);
  assertEquals(data.subarray(8 + spec.length), new Uint8Array([0, 0, 0]));

  const dataReq = packMcDataReq({
    srcType: 0,
    dstType: 0,
    dispatchId: 2,
    data,
  });
  assertEquals(
    decodeFields(dataReq).map((f) => f.tag),
    [1, 2, 3, 4],
  );

  const mc = packPlanetMcMsg(
    { cid: crypto.randomUUID(), srcChanId: 1n, dstChanId: 2n },
    wrapMcMsg(MC_MSG.DATA_REQ, dataReq),
  );
  assertEquals(
    decodeFields(mc).map((f) => f.tag),
    [1, 2],
  );
});

Deno.test("packMcDataRsp and packPlanetUeInfo match post-answer control shapes", () => {
  const data = packMcDataSessionPayload(
    packStrmSpec({
      strms: [
        {
          ssrc: 102,
          bitrate: { target: 32 },
          state: { paused: false, code: 0 },
          ptime: 40,
          retx: { periOn: true, periIntvMs: 40, periLossThre: [0, 0, 20] },
          fecLossThre: [],
        },
      ],
      fbIntv: 200,
      tp: 1,
      fbOn: true,
    }),
  );
  const rsp = packMcDataRsp({
    result: 0,
    relCode: 0,
    dispatchId: 2,
    data,
  });
  assertEquals(
    decodeFields(rsp).map((f) => f.tag),
    [1, 2, 4, 5],
  );
  const decoded = decodeMcDataRsp(rsp);
  assertEquals(decoded.result, 0);
  assertEquals(decoded.relCode, 0);
  assertEquals(decoded.dispatchId, 2);
  assertEquals(decoded.data, data);

  const req = packMcDataReq({
    srcType: 0,
    dstType: 0,
    dispatchId: 2,
    data: new Uint8Array([1, 2, 3]),
  });
  assertEquals(decodeMcDataReq(req), {
    srcType: 0,
    dstType: 0,
    dispatchId: 2,
    data: new Uint8Array([1, 2, 3]),
  });

  const ue = packPlanetUeInfo({ userId: "u00000000000000000000000000000000" });
  assertEquals(
    decodeFields(ue).map((f) => f.tag),
    [1],
  );
});

Deno.test("packPlanetUserAgent emits the native Android UA field layout", () => {
  const wire = packPlanetUserAgent({
    osName: "Android",
    osVersion: "36",
    deviceName: "Pixel 6a",
    appVersion: "12.1.13-63078245f",
    engineVersion: "8.2.0-694e2367",
    appReleaseInfo: "ANDROID\t26.6.2\tAndroid OS\t16",
    manufacturer: "google",
  });
  const fields = decodeFields(wire);
  assertEquals(
    fields.map((f) => f.tag),
    [1, 2, 3, 5, 6, 7, 8],
  );
  assertEquals(new TextDecoder().decode(fields[0].value as Uint8Array), "Android");
  assertEquals(new TextDecoder().decode(fields[2].value as Uint8Array), "Pixel 6a");
  assertEquals(new TextDecoder().decode(fields[6].value as Uint8Array), "google");
});

Deno.test("packPlanetFeatureRegister matches captured feature records", () => {
  assertEquals(
    packPlanetFeatureRegister(16, true, 0),
    new Uint8Array([0x08, 0x10, 0x10, 0x01, 0x18, 0x00]),
  );
  assertEquals(
    packPlanetFeatureRegister(17, false, 0),
    new Uint8Array([0x08, 0x11, 0x10, 0x00, 0x18, 0x00]),
  );
  assertEquals(
    packPlanetFeatureRegister(0, false, 0),
    new Uint8Array([0x08, 0x00, 0x10, 0x00, 0x18, 0x00]),
  );
});

Deno.test("packNativeSetupOffer emits the 311-byte native media offer shape", () => {
  const pub = new Uint8Array(33);
  pub[0] = 0x02;
  for (let i = 1; i < pub.length; i++) pub[i] = i;
  const nonce = new Uint8Array(16);
  for (let i = 0; i < nonce.length; i++) nonce[i] = 0xa0 + i;
  const secret = new Uint8Array(30);
  for (let i = 0; i < secret.length; i++) secret[i] = 0xc0 + i;

  const offer = packNativeSetupOffer({
    mediaPubKey: pub,
    mediaKeyId: 0x572ff1a1,
    mediaNonce: nonce,
    mediaSecret: secret,
  });
  assertEquals(offer.length, 311);
  const top = decodeFields(offer);
  assertEquals(
    top.map((f) => f.tag),
    [1, 1, 1, 2, 2, 3],
  );
  assertEquals(
    top.map((f) => (f.value as Uint8Array).length),
    [74, 79, 47, 61, 34, 4],
  );

  const names = top.slice(0, 3).map((f) => {
    const media = decodeFields(f.value as Uint8Array);
    const codec = decodeFields(media[0].value as Uint8Array);
    return new TextDecoder().decode(codec[0].value as Uint8Array);
  });
  assertEquals(names, ["A", "V", "D"]);

  const securityA = decodeFields(top[3].value as Uint8Array);
  const securityAInner = decodeFields(securityA[0].value as Uint8Array);
  assertEquals(securityA[0].tag, 3);
  assertEquals(securityAInner[0].value, pub);
  assertEquals(securityAInner[1].value, 0x572ff1a1n);
  assertEquals(securityAInner[2].value, nonce);

  const securityB = decodeFields(top[4].value as Uint8Array);
  const securityBInner = decodeFields(securityB[0].value as Uint8Array);
  assertEquals(securityB[0].tag, 2);
  assertEquals(securityBInner[0].value, secret);

  const decoded = decodeNativeSetupOffer(offer);
  assertEquals(
    decoded.media.map((m) => m.name),
    ["A", "V", "D"],
  );
  assertEquals(
    decoded.media.map((m) => m.rtpPort),
    [101, 111, 121],
  );
  assertEquals(decoded.mediaPubKey, pub);
  assertEquals(decoded.mediaKeyId, 0x572ff1a1);
  assertEquals(decoded.mediaNonce, nonce);
  assertEquals(decoded.mediaSecret, secret);
  assertEquals(decoded.version, { major: 0, mode: 3 });
});

Deno.test("wrapCcMsg/packPlanetCcMsg/packPlanetMsg nest a SETUP_REQ properly", () => {
  const setup = packCcSetupReq({ initiator: "uA", responder: "uB" });
  const ccBody = wrapCcMsg(CC_MSG.SETUP_REQ, setup);
  const ccMsg = packPlanetCcMsg({ cid: "call-001", srcChanId: 1n, dstChanId: 2n }, ccBody);
  const wire = packPlanetMsg(
    {
      userId: "uA",
      msgId: 1,
      sessId: new Uint8Array(16),
      tranId: new Uint8Array(16),
      tranSeq: 1,
      locNonce: 0n,
      rmtNonce: 0n,
    },
    { kind: "cc", data: ccMsg },
  );
  // Outer must have field 1 (hdr) and field 3 (cc_msg as bytes)
  const outerFields = decodeFields(wire);
  assertEquals(outerFields[0].tag, 1);
  assertEquals(outerFields[1].tag, 3);
});

Deno.test("decodePlanetMsg unwraps cc setup_rsp", () => {
  const setupRsp = new Uint8Array([
    0x08,
    0x00, // result = 0
    0xa8,
    0x06,
    0x1e, // alive_rpt_interval = 30
    0x80,
    0x07,
    0x78, // no_ans_to_sec = 120
  ]);
  const ccMsg = packPlanetCcMsg(
    { cid: "call-001", srcChanId: 1n, dstChanId: 2n },
    wrapCcMsg(CC_MSG.SETUP_RSP, setupRsp),
  );
  const wire = packPlanetMsg(
    {
      userId: "uB",
      msgId: 2,
      sessId: new Uint8Array(16).fill(0xaa),
      tranId: new Uint8Array(16).fill(0xbb),
      tranSeq: 3,
      locNonce: 4n,
      rmtNonce: 5n,
    },
    { kind: "cc", data: ccMsg },
  );

  const decoded = decodePlanetMsg(wire);
  assertEquals(decoded.hdr?.msgId, 2);
  assertEquals(decoded.hdr?.sessId, new Uint8Array(16).fill(0xaa));
  assertEquals(decoded.cc?.hdr?.cid, "call-001");
  assertEquals(decoded.cc?.bodyTag, CC_MSG.SETUP_RSP);
  assertEquals(decoded.cc?.bodyName, "setup_rsp");
  assertEquals(decodeCcSetupRsp(decoded.cc!.bodyBytes!).aliveRptInterval, 30);
  assertEquals(decodeCcSetupRsp(decoded.cc!.bodyBytes!).noAnsToSec, 120);
});

Deno.test("packCcConnReq/packCcConnRsp round-trip answered-call media fields", () => {
  const answer = new Uint8Array([1, 2, 3]);
  const ua = packPlanetUserAgent({
    osName: "Android",
    osVersion: "36",
    deviceName: "Pixel 6a",
  });
  const req = packCcConnReq({
    answer,
    mChanId: 0x11223344n,
    netType: 1,
    unavailToSec: 120,
    oCapas: [1, 2, 7],
    features: [packPlanetFeatureRegister(16, true, 0)],
    ua,
    mAddr: { ver: 4, trpt: 1, ip: "203.0.113.10", port: 12345 },
    reqRec: false,
  });
  const decodedReq = decodeCcConnReq(req);
  assertEquals(decodedReq.answer, answer);
  assertEquals(decodedReq.mChanId, 0x11223344n);
  assertEquals(decodedReq.netType, 1);
  assertEquals(decodedReq.unavailToSec, 120);
  assertEquals(decodedReq.oCapas, [1, 2, 7]);
  assertEquals(decodedReq.features.length, 1);
  assertEquals(decodedReq.ua, ua);
  assertEquals(decodedReq.mAddr, {
    ver: 4,
    trpt: 1,
    ip: "203.0.113.10",
    ports: undefined,
    port: 12345,
  });
  assertEquals(decodedReq.reqRec, false);

  const rsp = packCcConnRsp({
    result: 0,
    mChanId: 0x55667788n,
    netType: 1,
    unavailToSec: 120,
    ua,
  });
  const decodedRsp = decodeCcConnRsp(rsp);
  assertEquals(decodedRsp.result, 0);
  assertEquals(decodedRsp.mChanId, 0x55667788n);
  assertEquals(decodedRsp.netType, 1);
  assertEquals(decodedRsp.unavailToSec, 120);
  assertEquals(decodedRsp.ua, ua);
});

Deno.test("cc_verify_req/rsp use native Android field tags", () => {
  const ua = packPlanetUserAgent({ osName: "Android", osVersion: "36", deviceName: "Pixel" });
  const credential = new Uint8Array([1, 2, 3, 4]);
  const req = packCcVerifyReq({
    initiator: "u-caller",
    responder: "u-local",
    iZone: "JP",
    rZone: "JP",
    ua,
    devId: "device",
    commTypeFlags: 1,
    capas: [1, 2, 7],
    credential,
    svcKey: "freecall.audio",
    crt: false,
    netType: 1,
    stid: "stid",
    svcId: "svc",
    tgtSvcId: "target",
    pathCheck: false,
    interDomain: false,
  });
  assertEquals(
    decodeFields(req).map((field) => field.tag),
    [1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 9, 10, 11, 12, 21, 51, 52, 105, 153],
  );

  const offer = new Uint8Array([9, 8, 7]);
  const feature = new Uint8Array([0x08, 0x01]);
  const rsp = packCcVerifyRsp({
    result: 0,
    relCode: 0,
    relPhrase: "OK",
    cfgs: "{}",
    oCapas: [1, 7],
    offer,
    releaser: "",
    compCfgs: new Uint8Array([5]),
    compCfgsType: 1,
    oUeData: new Uint8Array([6]),
    oUeDataCompType: 2,
    oFeatures: [feature],
    iCountry: "JP",
    iDevId: "peer-device",
    aliveRptInterval: 30,
    stops: "",
    pt: false,
    maxCallTimeSec: 3600,
  });
  const decoded = decodeCcVerifyRsp(rsp);
  assertEquals(decoded.result, 0);
  assertEquals(decoded.offer, offer);
  assertEquals(decoded.oCapas, [1, 7]);
  assertEquals(decoded.oFeatures, [feature]);
  assertEquals(decoded.iCountry, "JP");
  assertEquals(decoded.iDevId, "peer-device");
  assertEquals(decoded.aliveRptInterval, 30);
  assertEquals(decoded.maxCallTimeSec, 3600);
});

Deno.test("packCcInfoReq/packCcInfoRsp round-trip info exchange fields", () => {
  const body = new Uint8Array([1, 2, 3]);
  const ue = new Uint8Array([4, 5]);
  const req = packCcInfoReq({
    bodyType: "profile",
    body,
    targets: ["callee"],
    source: "caller",
    sourceSvcId: "freecall.audio",
    tgtUe: [ue],
    trxOrigin: "origin",
    svcId: "svc",
    tgtSvcId: "target",
    interDomain: false,
  });
  const decodedReq = decodeCcInfoReq(req);
  assertEquals(decodedReq.bodyType, "profile");
  assertEquals(decodedReq.body, body);
  assertEquals(decodedReq.targets, ["callee"]);
  assertEquals(decodedReq.source, "caller");
  assertEquals(decodedReq.sourceSvcId, "freecall.audio");
  assertEquals(decodedReq.tgtUe, [ue]);
  assertEquals(decodedReq.trxOrigin, "origin");
  assertEquals(decodedReq.svcId, "svc");
  assertEquals(decodedReq.tgtSvcId, "target");
  assertEquals(decodedReq.interDomain, false);

  const rsp = packCcInfoRsp({
    result: 0,
    bodyType: "profile",
    body,
    svcId: "svc",
    tgtSvcId: "target",
    interDomain: true,
  });
  const decodedRsp = decodeCcInfoRsp(rsp);
  assertEquals(decodedRsp.result, 0);
  assertEquals(decodedRsp.bodyType, "profile");
  assertEquals(decodedRsp.body, body);
  assertEquals(decodedRsp.svcId, "svc");
  assertEquals(decodedRsp.tgtSvcId, "target");
  assertEquals(decodedRsp.interDomain, true);
});

Deno.test("packCcRelReq matches the observed local-hangup field shape", () => {
  const wire = packCcRelReq({
    relCode: 2,
    releaser: "initiator",
    commMediaFlags: 1,
  });
  const fields = decodeFields(wire);
  assertEquals(
    fields.map((f) => [f.tag, f.wireType]),
    [
      [1, WireType.Varint],
      [3, WireType.LengthDelim],
      [4, WireType.Varint],
    ],
  );
  assertEquals(fields[0].value, 2n);
  assertEquals(new TextDecoder().decode(fields[1].value as Uint8Array), "initiator");
  assertEquals(fields[2].value, 1n);
});

Deno.test("packKeepaliveReq produces the captured msg #1 body (13 bytes)", () => {
  // captured ka_req inner body was `09 80 ee 7a 46 dc 56 b1 18 10 00`
  const ts = 0x18b156dc467aee80n;
  const inner = packKeepaliveReq(ts, false);
  assertEquals(
    inner,
    new Uint8Array([0x09, 0x80, 0xee, 0x7a, 0x46, 0xdc, 0x56, 0xb1, 0x18, 0x10, 0x00]),
  );
  const decoded = decodeFields(inner);
  assertEquals(decoded[0].tag, 1);
  assertEquals(decoded[0].wireType, WireType.Fixed64);
  assertEquals(decoded[0].value, ts);
  assertEquals(decoded[1].tag, 2);
  assertEquals(decoded[1].value, 0n);
});

Deno.test("extractRmtNonceFromReply pulls loc_nonce (field 6) out", async () => {
  const { extractRmtNonceFromReply, packPlanetMsgHdr } = await import("./schema.ts");
  // Build a reply header where the server's loc_nonce = 0x6a0e122c0e9d22ac
  const expected = 0x6a0e122c0e9d22acn;
  const hdr = packPlanetMsgHdr({
    userId: "u11111111111111111111111111111111",
    msgId: 1,
    sessId: new Uint8Array(16).fill(0xaa),
    tranId: new Uint8Array(16).fill(0xbb),
    tranSeq: 1,
    locNonce: expected, // cscf's local nonce — what becomes OUR rmt_nonce
    rmtNonce: 199820756n, // cscf knows our loc_nonce → echoes it back
  });
  const recovered = extractRmtNonceFromReply(hdr);
  assertEquals(recovered, expected);
});

Deno.test("encodeVarint matches well-known protobuf encodings", () => {
  assertEquals(encodeVarint(150), new Uint8Array([0x96, 0x01]));
  assertEquals(encodeVarint(4353), new Uint8Array([0x81, 0x22]));
  const [v, n] = decodeVarint(encodeVarint(7642030284661133203n), 0);
  assertEquals(v, 7642030284661133203n);
  assertEquals(n, 9);
});
