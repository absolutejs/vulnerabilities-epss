import type { FeedAdapter, FeedRecord } from "@absolutejs/vulnerabilities";

export const FIRST_EPSS_URL = "https://api.first.org/data/v1/epss";
export const FIRST_EPSS_MAX_URL_LENGTH = 2_000;
export const FIRST_EPSS_MAX_BATCH_SIZE = 100;

export type EpssScore = {
  cve: string;
  date: string;
  percentile: number;
  probability: number;
};

export type EpssFetch = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

type JsonObject = Record<string, unknown>;

const object = (value: unknown, label: string): JsonObject => {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error(`${label} must be an object`);
  return value as JsonObject;
};

const cve = (value: unknown) => {
  if (typeof value !== "string") throw new Error("EPSS CVE must be a string");
  const normalized = value.trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(normalized))
    throw new Error("EPSS CVE must be a CVE identifier");
  return normalized;
};

const day = (value: unknown) => {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value))
    throw new Error("EPSS date must use YYYY-MM-DD");
  return value;
};

const probability = (value: unknown, label: string) => {
  const normalized = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(normalized) || normalized < 0 || normalized > 1)
    throw new Error(`${label} must be between 0 and 1`);
  return normalized;
};

export const normalizeEpssResponse = (input: unknown): EpssScore[] => {
  const response = object(input, "EPSS response");
  if (response.status !== "OK" || response["status-code"] !== 200)
    throw new Error("EPSS response status must be OK/200");
  if (!Array.isArray(response.data))
    throw new Error("EPSS response data must be an array");
  const scores = response.data.map((entry) => {
    const score = object(entry, "EPSS score");
    return {
      cve: cve(score.cve),
      date: day(score.date),
      percentile: probability(score.percentile, "EPSS percentile"),
      probability: probability(score.epss, "EPSS probability"),
    };
  });
  if (new Set(scores.map(({ cve }) => cve)).size !== scores.length)
    throw new Error("EPSS response contains duplicate CVE identifiers");
  return scores;
};

const queryUrl = (baseUrl: string, cves: readonly string[], date?: string) => {
  const url = new URL(baseUrl);
  url.searchParams.set("cve", cves.join(","));
  url.searchParams.set("limit", String(FIRST_EPSS_MAX_BATCH_SIZE));
  if (date) url.searchParams.set("date", date);
  return url.toString();
};

export const batchEpssCves = (
  input: readonly string[],
  options: {
    baseUrl?: string;
    date?: string;
    maxBatchSize?: number;
    maxUrlLength?: number;
  } = {},
) => {
  const baseUrl = options.baseUrl ?? FIRST_EPSS_URL;
  const maxBatchSize = options.maxBatchSize ?? FIRST_EPSS_MAX_BATCH_SIZE;
  const maxUrlLength = options.maxUrlLength ?? FIRST_EPSS_MAX_URL_LENGTH;
  if (!Number.isInteger(maxBatchSize) || maxBatchSize < 1)
    throw new Error("EPSS maxBatchSize must be a positive integer");
  if (!Number.isInteger(maxUrlLength) || maxUrlLength < 1)
    throw new Error("EPSS maxUrlLength must be a positive integer");
  const normalized = [...new Set(input.map(cve))].sort();
  if (normalized.length === 0) throw new Error("At least one CVE is required");
  const batches: string[][] = [];
  let current: string[] = [];
  for (const id of normalized) {
    const candidate = [...current, id];
    if (
      current.length > 0 &&
      (candidate.length > maxBatchSize ||
        queryUrl(baseUrl, candidate, options.date).length > maxUrlLength)
    ) {
      batches.push(current);
      current = [id];
    } else {
      current = candidate;
    }
    if (queryUrl(baseUrl, current, options.date).length > maxUrlLength)
      throw new Error(`EPSS query for ${id} exceeds the URL length limit`);
  }
  batches.push(current);
  return batches;
};

export const createEpssAdapter = (options: {
  cves: readonly string[];
  date?: string;
  fetch?: EpssFetch;
  url?: string;
}): FeedAdapter<EpssScore> => {
  const url = options.url ?? FIRST_EPSS_URL;
  const dateFilter = options.date ? day(options.date) : undefined;
  const batches = batchEpssCves(options.cves, {
    baseUrl: url,
    ...(dateFilter ? { date: dateFilter } : {}),
  });
  const fetcher = options.fetch ?? globalThis.fetch;
  return {
    descriptor: { id: "first-epss", name: "FIRST EPSS", url },
    fetch: async ({ signal }) => {
      const byCve = new Map<string, EpssScore>();
      for (const batch of batches) {
        const response = await fetcher(queryUrl(url, batch, dateFilter), {
          signal,
        });
        if (!response.ok)
          throw new Error(
            `FIRST EPSS fetch failed with HTTP ${response.status}`,
          );
        for (const score of normalizeEpssResponse(await response.json())) {
          if (!batch.includes(score.cve))
            throw new Error(`EPSS returned unrequested CVE ${score.cve}`);
          if (byCve.has(score.cve))
            throw new Error(`EPSS returned duplicate CVE ${score.cve}`);
          byCve.set(score.cve, score);
        }
      }
      const scores = [...byCve.values()].sort((left, right) =>
        left.cve.localeCompare(right.cve),
      );
      const records: FeedRecord<EpssScore>[] = scores.map((value) => ({
        id: value.cve,
        modifiedAt: `${value.date}T00:00:00Z`,
        value,
      }));
      const revision = scores.reduce<string | null>(
        (latest, score) =>
          latest === null || score.date > latest ? score.date : latest,
        null,
      );
      return {
        cursor: { etag: null, lastModified: null, token: revision },
        fetchedAt: new Date().toISOString(),
        records,
        replaceAll: true,
        revision,
        status: "updated",
      };
    },
  };
};
