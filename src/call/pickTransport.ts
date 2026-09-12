/**
 * transport 選択 — commParam.mpkey → Planet、それ以外 → Andromeda
 * Desktop / ログイン端末 UA を Planet・SIP に渡す
 */

import type * as LINETypes from "@vyline/line-types";
import {
  AndromedaTransport,
  PlanetTransport,
  type CallTransport,
} from "@vyline/protocol/stack/call";
import type { CallWireContext } from "./context.js";
import { buildCallWireContext, describeRouteTransport } from "./context.js";
import type { Client } from "@vyline/protocol/stack";
import type { DesktopProfile } from "../desktop/types.js";

export function describeCallRoute(
  route: LINETypes.CallRoute | LINETypes.GroupCallRoute,
): "planet" | "andromeda" {
  return describeRouteTransport(route);
}

export function pickCallTransport(
  route: LINETypes.CallRoute | LINETypes.GroupCallRoute,
  ctx: CallWireContext,
  transportOpts?: { callId?: string; debug?: (event: Record<string, unknown>) => void },
): CallTransport {
  if (ctx.transportKind === "planet") {
    const planetOpts: ConstructorParameters<typeof PlanetTransport>[0] = {
      localMid: ctx.localMid,
      userAgent: ctx.planetUserAgent,
      ...(transportOpts?.callId ? { callId: transportOpts.callId } : {}),
      ...(transportOpts?.debug ? { debug: transportOpts.debug } : {}),
    };
    if (ctx.planetUserAgent.appReleaseInfo) {
      planetOpts.deviceInfo = ctx.planetUserAgent.appReleaseInfo;
    }
    return new PlanetTransport(planetOpts);
  }
  return new AndromedaTransport({
    localMid: ctx.localMid,
    userAgent: ctx.sipUserAgent,
  });
}

/** client + route から wire コンテキスト付き transport */
export function pickCallTransportForClient(
  client: Client,
  route: LINETypes.CallRoute | LINETypes.GroupCallRoute,
  opts?: {
    desktopProfile?: DesktopProfile | null;
    deviceMode?: string;
    callId?: string;
    debug?: (event: Record<string, unknown>) => void;
  },
): { transport: CallTransport; ctx: CallWireContext } {
  const ctx = buildCallWireContext(client, route, opts);
  const transportOpts =
    opts?.callId || opts?.debug
      ? {
          ...(opts.callId ? { callId: opts.callId } : {}),
          ...(opts.debug ? { debug: opts.debug } : {}),
        }
      : undefined;
  return {
    transport: pickCallTransport(route, ctx, transportOpts),
    ctx,
  };
}
