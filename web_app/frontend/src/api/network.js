import {
  authenticatedFetch,
} from "./client";


export async function getCommunications() {

  const response =
    await authenticatedFetch(
      "/api/network/communications/"
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
      "No fue posible obtener las comunicaciones."
    );
  }


  return data.communications;
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