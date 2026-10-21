/** Read-only presentation of NVD CPE discovery. No inferred validations. */
const LEVEL = {SPECIFIC:"Nivel 1 · Específico",FAMILY:"Nivel 2 · Familia",MANUFACTURER:"Nivel 3 · Fabricante",ALTERNATIVE:"Nivel 4 · Investigación alternativa",ADVANCED:"Búsqueda avanzada",CATALOGUE:"Selección desde catálogo NVD",LEGACY:"Consulta histórica"};
const OUTCOME = {
 EXPLORATORY_BRAND_MATCHES:"Se encontraron posibles diferencias de marca/proveedor; requieren comprobación del analista",
 SUFFICIENT_PERTINENT_CANDIDATES:"Coincidencia técnica suficiente para detener la ampliación",
 NO_PERTINENT_CANDIDATES:"Sin coincidencia técnica suficiente; se puede ampliar",
 PARTIAL_RESULTS:"Exploración incompleta; no descarta CPE",
};
const REASON = {
 NO_PERTINENT_CANDIDATES:"No hubo coincidencias técnicas suficientes",
 NO_NEW_PARAMETERS:"Se evitaron consultas duplicadas por falta de nuevos parámetros",
 GLOBAL_PAGE_LIMIT:"Se agotó el presupuesto global de páginas",
 GLOBAL_BUDGET_EXHAUSTED:"Se agotó el presupuesto compartido",
 MANUFACTURER_LEVEL_LIMIT:"Se alcanzó el límite compartido de consultas por fabricante",
 MANUFACTURER_PAGE_LIMIT:"Se alcanzó el límite de páginas de esta consulta al fabricante",
 PER_STRATEGY_PAGE_LIMIT:"Se alcanzó el límite de páginas de esta estrategia",
 CANDIDATE_LIMIT:"Se alcanzó el máximo de candidatos",
 REQUEST_FAILED:"La consulta a NVD no terminó correctamente",
 ADVANCED_PAGE_LIMIT:"Se alcanzó el número de páginas solicitado por el analista",
 ADVANCED_OFFSET:"Se inició desde una página posterior; no se examinaron todas las páginas anteriores",
};
const STATUSES = {COMPLETED:"Completada",RUNNING:"En ejecución",PARTIAL:"Parcial",SKIPPED:"No ejecutada",FAILED:"Fallida",PLANNED:"En cola"};
const CLASSIFICATION = {
 SPECIFIC:["Coincidencia técnica específica","specific"],
 SOFTWARE_EXACT:["Producto y versión coincidentes","specific"],
 SOFTWARE_BRANCH:["Misma rama de versión · verificar variante","family"],
 SOFTWARE_PRODUCT:["Producto coincidente · versión no comprobada","related"],
 FAMILY:["Coincidencia de familia","family"],
 RELATED:["Producto relacionado","related"],
 EXPLORATORY:["Correspondencia débil · exploratoria","related"],
 NEEDS_INFO:["Requiere información adicional","needs-info"],
 POSSIBLE_INCOMPATIBILITY:["Posible incompatibilidad","incompatible"],
};
const ORDER=["SPECIFIC","FAMILY","MANUFACTURER","ALTERNATIVE","ADVANCED","CATALOGUE"];
export const levelName = level => LEVEL[level] || "Nivel no registrado";
export const resultLabel = value => OUTCOME[value] || (value ? "Resultado sin descripción registrada" : "Sin evaluación registrada");
export const reasonLabel = value => REASON[value] || (value ? "Motivo técnico: " + value : "");
export const queryStatusLabel = value => STATUSES[value] || (value || "Sin estado registrado");
export function queryDescription(q) {
 if (q?.strategy === "keywordSearch") return "Búsqueda textual";
 if (q?.strategy !== "cpeMatchString") return "Consulta";
 const parts=String(q.parameter || "").split(":");
 if (parts.length<4) return "Identificador CPE";
 const category=parts[2]==="o" ? "Sistema operativo" :
   parts[2]==="a" ? "Aplicación" : "Hardware";
 const product=parts[4] && parts[4]!=="*" ? " · producto " + parts[4] : " · catálogo general";
 const version=parts[5] && parts[5]!=="*" ? " · versión/prefijo " + parts[5] : "";
 return category + " · fabricante " + parts[3] + product + version;
}
const num=v=>v===null||v===undefined||!Number.isFinite(Number(v))||Number(v)<0 ? null : Number(v);
export function groupCpeQueries(queries=[]) {
 const groups=[];
 for (const q of Array.isArray(queries)?queries:[]) {
  if (!q || typeof q!=="object") continue;
  const level=ORDER.includes(q.level)?q.level:"LEGACY";
  let g=groups[groups.length-1];
  if (!g || g.level!==level) {
   g={level,queries:[],pages:0,retrieved:0,hardware:0,filtered:0,
      hasPages:false,hasRetrieved:false,result:"",nextReason:"",stopReason:"",
      uniqueCandidates:null,pertinentCandidates:null,status:""};
   groups.push(g);
  }
  g.queries.push(q);
  for (const [key,field] of [["pages","pages"],["retrieved","retrieved"],["hardware","hardware_results"],["filtered","filtered_hardware_results"]]) {
   const n=num(q[field]); if(n!==null){g[key]+=n;if(key==="pages")g.hasPages=true;if(key==="retrieved")g.hasRetrieved=true;}
  }
  if(q.level_result)g.result=q.level_result;
  if(q.next_level_reason)g.nextReason=q.next_level_reason;
  if(q.stop_reason)g.stopReason=q.stop_reason;
  if(q.status)g.status=q.status;
  if(num(q.level_unique_hardware_candidates)!==null)g.uniqueCandidates=num(q.level_unique_hardware_candidates);
  if(num(q.level_pertinent_candidates)!==null)g.pertinentCandidates=num(q.level_pertinent_candidates);
 }
 return groups;
}
export function describeCandidate(candidate={}) {
 const [label,tone]=CLASSIFICATION[candidate?.match_level]||["Sin clasificación registrada","unknown"];
 return {label,tone,reason:typeof candidate.match_reason==="string"&&candidate.match_reason?candidate.match_reason:"No se conserva el motivo de clasificación.",
  levels:Array.isArray(candidate.discovery_levels)?ORDER.filter(x=>candidate.discovery_levels.includes(x)).map(levelName):[],
  methods:Array.isArray(candidate.methods)?[...new Set(candidate.methods.filter(x=>typeof x==="string"))]:[]};
}
