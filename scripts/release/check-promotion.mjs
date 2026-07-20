import { promotionFailures } from "./release-lib.mjs";

const missing = promotionFailures();
throw new Error(`formal promotion is disabled; missing external attestations: ${missing.join(", ")}`);
