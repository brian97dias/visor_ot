import {
  authenticatedFetch,
} from "./client";


export async function getCommunications({
  page = 1,
  search = "",
  status = "ALL",
  minPackets = 1,
  includeInactive = false,
} = {}) {
  const params = new URLSearchParams({
    page: String(page),
    search,
    status,
    min_packets: String(minPackets),
    include_inactive: String(includeInactive),
  });

  const response = await authenticatedFetch(
    "/api/network/communications/?" + params.toString()
  );

  let data = {};
  try {
    data = await response.json();
  } catch {
    throw new Error("El servidor devolvió una respuesta inválida.");
  }

  if (!response.ok) {
    throw new Error(data.detail || "No fue posible obtener las comunicaciones.");
  }

  if (!Array.isArray(data.results)) {
    throw new Error("La respuesta no contiene una página de comunicaciones.");
  }

  return data;
}


export async function getCommunication(
  communicationId
) {

  const response =
    await authenticatedFetch(
      `/api/network/communications/${communicationId}/`
    );


  let data = {};

  try {
    data = await response.json();
  } catch {
    throw new Error(
      "El servidor devolvió una respuesta inválida."
    );
  }


  if (!response.ok) {
    throw new Error(
      data.detail ||
      "No fue posible obtener la comunicación."
    );
  }


  return data;
}


export async function classifyCommunication(
  communicationId,
  status
) {

  const response =
    await authenticatedFetch(
      `/api/network/communications/${communicationId}/classification/`,
      {
        method: "PATCH",

        headers: {
          "Content-Type": "application/json",
        },

        body: JSON.stringify({
          status,
        }),
      }
    );


  let data = {};

  try {
    data = await response.json();
  } catch {
    throw new Error(
      "El servidor devolvió una respuesta inválida."
    );
  }


  if (!response.ok) {
    throw new Error(
      data.detail ||
      "No fue posible clasificar la comunicación."
    );
  }


  return data;
}