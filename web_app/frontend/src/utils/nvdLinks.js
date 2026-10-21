/** Official NVD API links. These resolve live JSON, NOT archived responses. */
const ENDPOINT = "https://services.nvd.nist.gov/rest/json/cpes/2.0";
export const NVD_PAGE_SIZE = 100;

export function nvdQueryUrl(query, page = 0) {
  if (!query || !["keywordSearch", "cpeMatchString"].includes(query.strategy)
      || typeof query.parameter !== "string" || !Number.isInteger(page) || page < 0) {
    return null;
  }
  const initial = Number.isInteger(query.start_index) && query.start_index >= 0
    ? query.start_index : 0;
  // URL-encode untrusted parameter contents, but preserve the visible CPE
  // colon/wildcard syntax the analyst entered in the original query.
  const parameter = encodeURIComponent(query.parameter)
    .replace(/%3A/gi, ":").replace(/%2A/gi, "*");
  const base = ENDPOINT + "?" + query.strategy + "=" + parameter;
  // The first CPE link reproduces the exact query shown in the trace.
  // Only explicit later pages/offsets need pagination controls.
  if (query.strategy === "cpeMatchString" && page === 0 && initial === 0) {
    return base;
  }
  return base + "&startIndex=" + (initial + page * NVD_PAGE_SIZE)
    + "&resultsPerPage=" + NVD_PAGE_SIZE;
}

export function nvdCpeUrl(nameId) {
  if (typeof nameId !== "string" ||
      !/^[a-f\d]{8}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{12}$/i.test(nameId)) {
    return null;
  }
  const url = new URL(ENDPOINT);
  url.searchParams.set("cpeNameId", nameId);
  return url.toString();
}
