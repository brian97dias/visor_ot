/** Official NVD API links. These resolve live JSON, NOT archived responses. */
const ENDPOINT = "https://services.nvd.nist.gov/rest/json/cpes/2.0";
export const NVD_PAGE_SIZE = 100;

export function nvdQueryUrl(query, page = 0) {
  if (!query || !["keywordSearch", "cpeMatchString"].includes(query.strategy)
      || typeof query.parameter !== "string" || !Number.isInteger(page) || page < 0) {
    return null;
  }
  const url = new URL(ENDPOINT);
  url.searchParams.set(query.strategy, query.parameter);
  url.searchParams.set("startIndex", String(page * NVD_PAGE_SIZE));
  url.searchParams.set("resultsPerPage", String(NVD_PAGE_SIZE));
  return url.toString();
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
