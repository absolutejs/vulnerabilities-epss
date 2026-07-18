import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<Record<string, never>>()({
  contract: 2,
  discovery: {
    audiences: ["platform-operators", "security-teams"],
    intents: [
      "ingest FIRST EPSS scores",
      "prioritize CVEs by exploitation probability",
      "enrich vulnerability risk assessments",
    ],
    keywords: ["FIRST", "EPSS", "CVE", "probability", "percentile"],
    protocols: ["FIRST EPSS API v1"],
  },
  identity: {
    accent: "#6d28d9",
    category: "operations",
    description:
      "Official FIRST EPSS probability and percentile ingestion with bounded batches and strict score validation.",
    docsUrl: "https://github.com/absolutejs/vulnerabilities-epss",
    name: "@absolutejs/vulnerabilities-epss",
    tagline: "Prioritize CVEs by predicted exploitation probability.",
  },
  settings: Type.Object({}),
  wiring: [],
});
