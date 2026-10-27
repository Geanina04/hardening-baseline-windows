(function(root){'use strict';
const states=['Cumple','No cumple','No aplica','No evaluado','Error de evaluación'];
const risks=['Alto','Medio','Bajo'];
function summary(controls){
  const count=s=>controls.filter(c=>c.estado===s).length;
  const pass=count('Cumple'),fail=count('No cumple'),den=pass+fail;
  return {total:controls.length,evaluados:den,cumplen:pass,no_cumplen:fail,no_aplica:count('No aplica'),no_evaluados:count('No evaluado'),errores:count('Error de evaluación'),porcentaje_cumplimiento:den?Math.round(pass/den*10000)/100:null};
}
function validate(d){
  const fail=msg=>{throw new Error(msg)};
  if(!d||typeof d!=='object'||Array.isArray(d))fail('El archivo debe contener un objeto JSON de auditoría.');
  if(d.schema_version!=='1.0')fail('Versión de esquema incompatible. Se requiere schema_version: 1.0.');
  for(const k of ['baseline_id','ejecucion_id','fecha','etapa','origen'])if(typeof d[k]!=='string'||!d[k].length||d[k].length>200)fail('Metadato inválido: '+k+'.');
  if(!['real','simulado'].includes(d.origen))fail('origen debe indicar real o simulado.');
  if(!['inicial','posterior','reversion','diagnostico','ejemplo'].includes(d.etapa))fail('Etapa desconocida.');
  if(!Number.isFinite(Date.parse(d.fecha)))fail('Fecha de ejecución inválida.');
  if(!d.sistema||typeof d.sistema.nombre!=='string'||typeof d.sistema.compilacion!=='string'||typeof d.sistema.administrador!=='boolean')fail('Faltan metadatos de Windows: nombre, compilacion o administrador.');
  if(!Array.isArray(d.controles)||d.controles.length===0||d.controles.length>1000)fail('controles debe ser una lista de 1 a 1000 elementos.');
  const ids=new Set();
  for(const [i,c] of d.controles.entries()){
    if(!c||typeof c!=='object'||Array.isArray(c))fail('Control inválido en posición '+(i+1)+'.');
    if(typeof c.id!=='string'||!/^[-A-Za-z0-9]{1,40}$/.test(c.id)||ids.has(c.id))fail('Identificador inválido o duplicado en posición '+(i+1)+'.');
    ids.add(c.id);
    for(const k of ['nombre','esperado','explicacion','justificacion','recomendacion','efectos_secundarios','aplicabilidad','fuente','fecha'])if(typeof c[k]!=='string'||!c[k].trim()||c[k].length>10000)fail(c.id+': falta o es inválido el campo '+k+'.');
    if(!states.includes(c.estado))fail(c.id+': estado desconocido.');
    if(!risks.includes(c.riesgo))fail(c.id+': riesgo desconocido.');
    if(!Object.hasOwn(c,'actual')||(!['string','number','boolean'].includes(typeof c.actual)&&c.actual!==null))fail(c.id+': valor actual debe ser escalar o null.');
    if(typeof c.actual==='number'&&!Number.isFinite(c.actual))fail(c.id+': número inválido.');
    if(['Cumple','No cumple'].includes(c.estado)&&c.actual===null)fail(c.id+': un control evaluado no puede tener valor null.');
    if(c.error!==null&&typeof c.error!=='string')fail(c.id+': error debe ser texto o null.');
    if(['No evaluado','Error de evaluación'].includes(c.estado)&&!c.error)fail(c.id+': debe explicar por qué no se evaluó.');
    if(!Number.isFinite(Date.parse(c.fecha)))fail(c.id+': fecha inválida.');
  }
  const computed=summary(d.controles);
  if(!d.resumen||typeof d.resumen!=='object')fail('Falta el resumen.');
  for(const [k,v] of Object.entries(computed))if(d.resumen[k]!==v)fail('Resumen inconsistente: '+k+'. Se esperaba '+v+'.');
  return d;
}
function compare(a,b){
  validate(a);validate(b);
  if(a.baseline_id!==b.baseline_id)throw new Error('No se pueden comparar perfiles de baseline distintos.');
  if(a.sistema.nombre!==b.sistema.nombre||a.sistema.compilacion!==b.sistema.compilacion)throw new Error('Los archivos corresponden a versiones de Windows distintas.');
  if(a.origen!==b.origen)throw new Error('No mezcles resultados reales con datos simulados.');
  const before=new Map(a.controles.map(c=>[c.id,c])),after=new Map(b.controles.map(c=>[c.id,c]));
  const rows=[...new Set([...before.keys(),...after.keys()])].map(id=>{
    const x=before.get(id),y=after.get(id);let cambio='No comparable';
    if(x&&y&&x.esperado===y.esperado&&['Cumple','No cumple'].includes(x.estado)&&['Cumple','No cumple'].includes(y.estado))cambio=x.estado===y.estado?'Igual':y.estado==='Cumple'?'Mejoró':'Empeoró';
    return {id,nombre:(y||x).nombre,antes:x?x.estado:'Ausente',despues:y?y.estado:'Ausente',cambio};
  });
  const sa=summary(a.controles),sb=summary(b.controles),delta=sa.porcentaje_cumplimiento===null||sb.porcentaje_cumplimiento===null?null:Math.round((sb.porcentaje_cumplimiento-sa.porcentaje_cumplimiento)*100)/100;
  const common=rows.filter(r=>r.cambio!=='No comparable');
  const commonDelta=common.length?Math.round((common.filter(r=>r.despues==='Cumple').length-common.filter(r=>r.antes==='Cumple').length)/common.length*10000)/100:null;
  return {rows,antes:sa,despues:sb,delta,denominador_comun:common.length,delta_comun:commonDelta};
}
const api={states,risks,summary,validate,compare};if(typeof module!=='undefined')module.exports=api;else root.BaselineModel=api;
})(typeof window!=='undefined'?window:globalThis);
