import type { VylineLoginInit } from "./VylineClient.js";

type StorageIsRequired = {} extends Pick<VylineLoginInit, "storage"> ? false : true;

const persistenceMustBeInjected: StorageIsRequired = true;
void persistenceMustBeInjected;
