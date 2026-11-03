import {
  useEffect,
  useState,
} from "react";

import {
  Link,
  useLocation,
  useParams,
  useOutletContext,
} from "react-router-dom";

import {
  classifyCommunication,
  getCommunication,
} from "../api/network";
import CommunicationEndpoint from "../components/CommunicationEndpoint";
import { getBackNavigation, navigationFromLocation } from "../utils/returnNavigation";


function getStatusLabel(status) {

  const labels = {
    NO_CLASIFICADA:
      "No clasificada",

    AUTORIZADA:
      "Autorizada",

    NO_AUTORIZADA:
      "No autorizada",
  };

  return labels[status] || status;
}


function getStatusClass(status) {

  const classes = {
    NO_CLASIFICADA:
      "status status-unclassified",

    AUTORIZADA:
      "status status-authorized",

    NO_AUTORIZADA:
      "status status-unauthorized",
  };

  return (
    classes[status]
    || "status status-unclassified"
  );
}


function CommunicationDetail() {
  const { user } = useOutletContext();
  const location = useLocation();
  const back = getBackNavigation(location, "/communications");
  const navigationState = navigationFromLocation(location);
  const canClassify = user?.role === "ADMIN" || user?.role === "ANALYST";

  const {
    communicationId,
  } = useParams();


  const [
    communication,
    setCommunication,
  ] = useState(null);

  const [
    selectedStatus,
    setSelectedStatus,
  ] = useState("");

  const [
    saving,
    setSaving,
  ] = useState(false);

  const [
    loading,
    setLoading,
  ] = useState(true);

  const [
    error,
    setError,
  ] = useState("");

  const [
    notice,
    setNotice,
  ] = useState("");


  useEffect(() => {

    async function loadCommunication() {

      try {

        const data =
          await getCommunication(
            communicationId
          );

        setCommunication(
          data
        );

        setSelectedStatus(
          data.status
        );


      } catch (error) {

        setError(
          error.message
        );


      } finally {

        setLoading(false);

      }

    }


    loadCommunication();

  }, [communicationId]);


  const handleClassification =
    async () => {

      setError("");
      setNotice("");
      setSaving(true);


      try {

        const updated =
          await classifyCommunication(
            communicationId,
            selectedStatus
          );


        setCommunication(
          updated
        );

        setSelectedStatus(
          updated.status
        );

        setNotice(
          "Clasificación actualizada correctamente."
        );


      } catch (error) {

        setError(
          error.message
        );


      } finally {

        setSaving(false);

      }

    };


  if (loading) {

    return (
      <section className="page">
        <p>
          Cargando comunicación...
        </p>
      </section>
    );

  }


  if (error && !communication) {

    return (
      <section className="page">
        <div className="error-message">
          {error}
        </div>
      </section>
    );

  }


  return (
    <section className="page">

      <div className="breadcrumbs">

        <span>
          Red
        </span>

        <span>/</span>

        <Link to={back.to} state={back.state}>
          Comunicaciones
        </Link>

        <span>/</span>

        <span>
          #{communication.id}
        </span>

      </div>


      <Link className="button-secondary assets-back-link" to={back.to} state={back.state}>← Volver</Link>
      <header className="analysis-detail-header">

        <div>

          <div className="analysis-title-row">

            <h1>
              Comunicación #{communication.id}
            </h1>


            <span
              className={
                getStatusClass(
                  communication.status
                )
              }
            >
              {
                getStatusLabel(
                  communication.status
                )
              }
            </span>


            {
              communication.active_evidence_count
              === 0
              && (
                <span className="status status-no-evidence">
                  Sin evidencia activa
                </span>
              )
            }

          </div>


          <p>
            Comunicación consolidada
            a partir de observaciones
            importadas.
          </p>

        </div>

      </header>


      {error && (

        <div className="error-message dismissible-message">

          <span>
            {error}
          </span>

          <button
            className="message-close"
            onClick={() =>
              setError("")
            }
          >
            ×
          </button>

        </div>

      )}


      {notice && (

        <div className="success-message dismissible-message">

          <span>
            {notice}
          </span>

          <button
            className="message-close"
            onClick={() =>
              setNotice("")
            }
          >
            ×
          </button>

        </div>

      )}


      <div className="analysis-metadata">

        <div>
          <span>Origen</span>

          <CommunicationEndpoint ip={communication.source_ip}
            resolution={communication.source_resolution} />
        </div>


        <div>
          <span>Destino</span>

          <CommunicationEndpoint ip={communication.destination_ip}
            resolution={communication.destination_resolution} />
        </div>


        <div>
          <span>Transporte</span>

          <strong>
            {
              communication.transport_protocol
            }
          </strong>
        </div>


        <div>
          <span>Puerto de servicio</span>

          <strong>
            {communication.transport_protocol === "ETHERNET"
              ? "No aplica (Ethernet)"
              : communication.service_port}
          </strong>
        </div>


        <div>
          <span>Servicio</span>

          <strong>
            {
              communication.service
              || "No identificado"
            }
          </strong>
        </div>


        <div>
          <span>Evidencias activas</span>

          <strong>
            {
              communication.active_evidence_count
            }
          </strong>
        </div>

      </div>


      <div className="analysis-summary">

        <div className="summary-card">

          <span>
            Paquetes observados
          </span>

          <strong>
            {
              communication.packets_observed
                .toLocaleString(
                  "es-CO"
                )
            }
          </strong>

        </div>


        <div className="summary-card">

          <span>
            Primera observación
          </span>

          <strong className="summary-date">
            {
              communication.first_seen
              || "Sin evidencia activa"
            }
          </strong>

        </div>


        <div className="summary-card">

          <span>
            Última observación
          </span>

          <strong className="summary-date">
            {
              communication.last_seen
              || "Sin evidencia activa"
            }
          </strong>

        </div>

      </div>


      <div className="classification-panel">

        <div>

          <h2>
            Clasificación
          </h2>

          <p>
            Determina si esta comunicación
            está autorizada dentro de la red OT.
          </p>

        </div>


        {canClassify && <div className="classification-controls">

          <select
            value={selectedStatus}
            onChange={
              (event) =>
                setSelectedStatus(
                  event.target.value
                )
            }
          >
            <option value="NO_CLASIFICADA">
              No clasificada
            </option>

            <option value="AUTORIZADA">
              Autorizada
            </option>

            <option value="NO_AUTORIZADA">
              No autorizada
            </option>
          </select>


          <button
            className="button-primary"
            onClick={
              handleClassification
            }
            disabled={saving}
          >
            {
              saving
                ? "Guardando..."
                : "Guardar clasificación"
            }
          </button>

        </div>}


        {
          communication.classified_by
          && (
            <p className="classification-audit">
              Última clasificación por
              {" "}
              <strong>
                {
                  communication.classified_by
                }
              </strong>

              {
                communication.classified_at
                && (
                  <>
                    {" · "}
                    {
                      new Date(
                        communication.classified_at
                      ).toLocaleString(
                        "es-CO"
                      )
                    }
                  </>
                )
              }
            </p>
          )
        }

      </div>


      <div className="panel">

        <div className="panel-header">

          <div>

            <h2>
              Evidencias
            </h2>

            <p>
              Observaciones que han contribuido
              a esta comunicación consolidada.
            </p>

          </div>


          <span className="record-count">
            {
              communication.evidences.length
            }
            {" "}
            observaciones
          </span>

        </div>


        <div className="table-container">

          <table className="data-table">

            <thead>
              <tr>
                <th>Observación</th>
                <th>Ingesta</th>
                <th>Archivo</th>
                <th>Estado</th>
                <th>Paquetes</th>
                <th>Primera observación</th>
                <th>Última observación</th>
                <th>Acción</th>
              </tr>
            </thead>


            <tbody>

              {
                communication.evidences.map(
                  (evidence) => (

                    <tr
                      key={
                        evidence.id
                      }
                    >

                      <td>
                        #{evidence.id}
                      </td>


                      <td>
                        #{evidence.ingestion_id}
                      </td>


                      <td>
                        {
                          evidence.ingestion_filename
                        }
                      </td>


                      <td>

                        <span
                          className={
                            evidence.ingestion_status
                            === "ACTIVE"
                              ? "status status-analyzed"
                              : "status status-excluded"
                          }
                        >
                          {
                            evidence.ingestion_status
                            === "ACTIVE"
                              ? "Activa"
                              : "Excluida"
                          }
                        </span>

                      </td>


                      <td>
                        {
                          evidence.packet_count
                            .toLocaleString(
                              "es-CO"
                            )
                        }
                      </td>


                      <td>
                        {
                          evidence.first_seen
                        }
                      </td>


                      <td>
                        {
                          evidence.last_seen
                        }
                      </td>


                      <td>

                        <Link
                          className="button-link"
                          to={`/passive-analysis/imports/${evidence.ingestion_id}`} state={navigationState}
                        >
                          Ver ingesta
                        </Link>

                      </td>

                    </tr>

                  )
                )
              }

            </tbody>

          </table>

        </div>

      </div>

    </section>
  );
}


export default CommunicationDetail;