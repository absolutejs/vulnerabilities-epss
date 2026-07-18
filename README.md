# @absolutejs/vulnerabilities-epss

Official FIRST Exploit Prediction Scoring System ingestion for
`@absolutejs/vulnerabilities`.

```ts
import { createEpssAdapter } from "@absolutejs/vulnerabilities-epss";

const adapter = createEpssAdapter({
  cves: ["CVE-2021-44228", "CVE-2024-3094"],
});
```

The adapter normalizes EPSS probability and percentile values to numbers from
zero through one. It deduplicates and validates CVE identifiers, limits each
request to 100 CVEs, keeps encoded URLs below 2,000 characters, rejects
unrequested provider records, and emits the EPSS scoring date as its revision.
