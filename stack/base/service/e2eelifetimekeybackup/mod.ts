// Hand-written service wrapper (mirrors gen_services.ts output style).
// Endpoint per q0jt/line-sbc resource/README.md:
//   E2EELifetimeKeyBackupService(/LKBS4)
// Thrift 定義は line-sbc resource/backup.thrift 由来。struct は
// @vyline/line-types に手書き追加（restoreLifetimeKeyBackupHeader_args 等）。
import { type BaseClient } from "../../core/mod.js";
import type { ProtocolKey } from "../../thrift/mod.js";
import type { BaseService } from "../types.ts";
import { LINEStruct } from "../../thrift/mod.js";
import type * as LINETypes from "@vyline/line-types";

export class E2EELifetimeKeyBackupService implements BaseService {
  client: BaseClient;
  protocolType: ProtocolKey = 4;
  requestPath = "/LKBS4";
  errorName = "E2EELifetimeKeyBackupServiceError";
  constructor(client: BaseClient) {
    this.client = client;
  }

  async createLifetimeKeyBackup(
    ...param: Parameters<typeof LINEStruct.createLifetimeKeyBackup_args>
  ): Promise<LINETypes.createLifetimeKeyBackup_result["success"]> {
    return await this.client.request.request(
      LINEStruct.createLifetimeKeyBackup_args(...param),
      "createLifetimeKeyBackup",
      this.protocolType,
      true,
      this.requestPath,
    );
  }

  async restoreLifetimeKeyBackupHeader(
    ...param: Parameters<typeof LINEStruct.restoreLifetimeKeyBackupHeader_args>
  ): Promise<LINETypes.restoreLifetimeKeyBackupHeader_result["success"]> {
    return await this.client.request.request(
      LINEStruct.restoreLifetimeKeyBackupHeader_args(...param),
      "restoreLifetimeKeyBackupHeader",
      this.protocolType,
      true,
      this.requestPath,
    );
  }

  async validateLifetimeKeyBackup(
    ...param: Parameters<typeof LINEStruct.validateLifetimeKeyBackup_args>
  ): Promise<LINETypes.validateLifetimeKeyBackup_result["success"]> {
    return await this.client.request.request(
      LINEStruct.validateLifetimeKeyBackup_args(...param),
      "validateLifetimeKeyBackup",
      this.protocolType,
      true,
      this.requestPath,
    );
  }

  async addLifetimeKeyBackupPayloadDataList(
    ...param: Parameters<typeof LINEStruct.addLifetimeKeyBackupPayloadDataList_args>
  ): Promise<LINETypes.addLifetimeKeyBackupPayloadDataList_result["success"]> {
    return await this.client.request.request(
      LINEStruct.addLifetimeKeyBackupPayloadDataList_args(...param),
      "addLifetimeKeyBackupPayloadDataList",
      this.protocolType,
      true,
      this.requestPath,
    );
  }

  async updateLifetimeKeyBackupHeader(
    ...param: Parameters<typeof LINEStruct.updateLifetimeKeyBackupHeader_args>
  ): Promise<void> {
    await this.client.request.request(
      LINEStruct.updateLifetimeKeyBackupHeader_args(...param),
      "updateLifetimeKeyBackupHeader",
      this.protocolType,
      true,
      this.requestPath,
    );
  }

  async getLifetimeKeyBackupPayloadDataList(
    ...param: Parameters<typeof LINEStruct.getLifetimeKeyBackupPayloadDataList_args>
  ): Promise<LINETypes.getLifetimeKeyBackupPayloadDataList_result["success"]> {
    return await this.client.request.request(
      LINEStruct.getLifetimeKeyBackupPayloadDataList_args(...param),
      "getLifetimeKeyBackupPayloadDataList",
      this.protocolType,
      true,
      this.requestPath,
    );
  }
}
