import { describe, expect, test } from "bun:test";
import {
  batchEpssCves,
  createEpssAdapter,
  normalizeEpssResponse,
  type EpssFetch,
} from "../src";

const response = {
  access: "public",
  data: [
    {
      cve: "CVE-2021-44228",
      date: "2026-07-18",
      epss: "0.999990000",
      percentile: "1.000000000",
    },
  ],
  limit: 100,
  offset: 0,
  status: "OK",
  "status-code": 200,
  total: 1,
  version: "1.0",
};

describe("FIRST EPSS normalization", () => {
  test("normalizes probability strings into bounded numbers", () => {
    expect(normalizeEpssResponse(response)).toEqual([
      {
        cve: "CVE-2021-44228",
        date: "2026-07-18",
        percentile: 1,
        probability: 0.99999,
      },
    ]);
  });

  test("rejects out-of-range probabilities and invalid envelopes", () => {
    expect(() =>
      normalizeEpssResponse({
        ...response,
        data: [{ ...response.data[0], epss: "1.1" }],
      }),
    ).toThrow("between 0 and 1");
    expect(() =>
      normalizeEpssResponse({ ...response, status: "ERROR" }),
    ).toThrow("OK/200");
  });
});

describe("FIRST EPSS batching", () => {
  test("deduplicates CVEs and respects batch limits", () => {
    expect(
      batchEpssCves(["cve-2026-0002", "CVE-2026-0001", "CVE-2026-0002"], {
        maxBatchSize: 1,
      }),
    ).toEqual([["CVE-2026-0001"], ["CVE-2026-0002"]]);
  });

  test("splits requests before they exceed the URL limit", () => {
    const batches = batchEpssCves(
      ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"],
      { maxUrlLength: 75 },
    );
    expect(batches.length).toBeGreaterThan(1);
  });
});

describe("FIRST EPSS adapter", () => {
  test("returns risk-enrichment records and a daily revision", async () => {
    let requestedUrl = "";
    const fetcher: EpssFetch = async (input) => {
      requestedUrl = String(input);
      return Response.json(response);
    };
    const result = await createEpssAdapter({
      cves: ["CVE-2021-44228"],
      fetch: fetcher,
    }).fetch({ cursor: null });
    expect(requestedUrl).toContain("cve=CVE-2021-44228");
    expect(result.status).toBe("updated");
    if (result.status !== "updated") throw new Error("Expected update");
    expect(result.records[0]?.value.probability).toBe(0.99999);
    expect(result.revision).toBe("2026-07-18");
    expect(result.cursor.token).toBe("2026-07-18");
  });

  test("rejects provider records that were not requested", async () => {
    const fetcher: EpssFetch = async () =>
      Response.json({
        ...response,
        data: [{ ...response.data[0], cve: "CVE-2026-9999" }],
      });
    const adapter = createEpssAdapter({
      cves: ["CVE-2021-44228"],
      fetch: fetcher,
    });
    expect(adapter.fetch({ cursor: null })).rejects.toThrow("unrequested CVE");
  });
});
