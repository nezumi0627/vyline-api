import { type BaseClient } from "../../core/mod.js";
import type { ProtocolKey } from "../../thrift/mod.js";
import type { BaseService } from "../types.ts";
import { LINEStruct } from "../../thrift/mod.js";
import type * as LINETypes from "@vyline/line-types";
export declare class E2EELifetimeKeyBackupService implements BaseService {
    client: BaseClient;
    protocolType: ProtocolKey;
    requestPath: string;
    errorName: string;
    constructor(client: BaseClient);
    createLifetimeKeyBackup(...param: Parameters<typeof LINEStruct.createLifetimeKeyBackup_args>): Promise<LINETypes.createLifetimeKeyBackup_result["success"]>;
    restoreLifetimeKeyBackupHeader(...param: Parameters<typeof LINEStruct.restoreLifetimeKeyBackupHeader_args>): Promise<LINETypes.restoreLifetimeKeyBackupHeader_result["success"]>;
    validateLifetimeKeyBackup(...param: Parameters<typeof LINEStruct.validateLifetimeKeyBackup_args>): Promise<LINETypes.validateLifetimeKeyBackup_result["success"]>;
    addLifetimeKeyBackupPayloadDataList(...param: Parameters<typeof LINEStruct.addLifetimeKeyBackupPayloadDataList_args>): Promise<LINETypes.addLifetimeKeyBackupPayloadDataList_result["success"]>;
    updateLifetimeKeyBackupHeader(...param: Parameters<typeof LINEStruct.updateLifetimeKeyBackupHeader_args>): Promise<void>;
    getLifetimeKeyBackupPayloadDataList(...param: Parameters<typeof LINEStruct.getLifetimeKeyBackupPayloadDataList_args>): Promise<LINETypes.getLifetimeKeyBackupPayloadDataList_result["success"]>;
}
