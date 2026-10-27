'use strict';
const $=id=>document.getElementById(id),M=window.BaselineModel;
let current=null,before=null,after=null;
const text=(tag,value,cls)=>{const e=document.createElement(tag);e.textContent=value;if(cls)e.className=cls;return e;};
const pct=v=>v===null?'Indeterminado':v.toLocaleString('es-CR',{maximumFractionDigits:2})+' %';
const value=v=>v===null?'Sin lectura':String(v);
const status=c=>text('span',c.estado,'status '+(c.estado==='Cumple'?'pass':c.estado==='No cumple'?'fail':'other'));
function message(msg,error=false,target='message'){$(target).textContent=msg;$(target).classList.toggle('error',error);}
async function read(file){
  if(!file||file.size===0)throw new Error('El archivo está vacío. Selecciona un JSON de auditoría.');
  if(file.size>5*1024*1024)throw new Error('El archivo supera el límite de 5 MiB.');
  let d;try{d=JSON.parse((await file.text()).replace(/^\uFEFF/,''));}catch{throw new Error('El JSON está dañado o no es válido. Vuelve a generarlo con PowerShell.');}
  return M.validate(d);
}
function load(d,label){
  current=M.validate(d);render();message('Auditoría cargada: '+label+'. '+(d.origen==='simulado'?'ATENCIÓN: datos simulados de prueba.':'Datos de una ejecución real.'));
}
function render(){
  const s=M.summary(current.controles),score=s.porcentaje_cumplimiento;
  $('score').textContent=pct(score);$('donut-number').textContent=score===null?'—':Math.round(score)+'%';
  const length=2*Math.PI*55;const filled=score===null?0:length*score/100;$('arc').setAttribute('stroke-dasharray',filled+' '+length);
  $('level').textContent=score===null?'Resultado indeterminado':score>=90?'Cumplimiento alto':score>=70?'Requiere mejoras':'Prioridad de revisión';
  $('denominator').textContent=s.cumplen+' de '+s.evaluados+' controles evaluables. No equivale a seguridad total.';
  for(const [id,key] of Object.entries({evaluated:'evaluados',pass:'cumplen',fail:'no_cumplen',na:'no_aplica',ne:'no_evaluados',errors:'errores'}))$(id).textContent=s[key];
  $('coverage').textContent='Cobertura: '+s.evaluados+'/'+s.total+' controles';
  $('dataset').textContent=(current.origen==='real'?'EJECUCIÓN REAL':'DATOS SIMULADOS')+' · '+current.etapa+' · '+current.sistema.nombre+' (build '+current.sistema.compilacion+') · '+new Date(current.fecha).toLocaleString('es-CR')+(current.sistema.administrador?' · Administrador':' · Sin elevación: revisar cobertura');
  $('export').disabled=false;$('print').disabled=false;
  const order={'Alto':0,'Medio':1,'Bajo':2};
  let findings=current.controles.filter(c=>c.estado!=='Cumple'&&c.estado!=='No aplica').sort((a,b)=>order[a.riesgo]-order[b.riesgo]).slice(0,3);
  if(!findings.length)findings=current.controles.slice(0,3);
  $('findings').replaceChildren(...findings.map(c=>{const e=text('article','','card finding');e.append(text('span',c.id+' / '+c.riesgo.toUpperCase(),'finding-id'),text('h3',c.nombre),status(c),text('p',c.error||c.recomendacion));return e;}));
  renderControls();
}
function field(title,content,cls=''){const div=text('div','',cls);div.append(text('h4',title),text('p',content));return div;}
function renderControls(){
  if(!current)return;
  const q=$('search').value.toLocaleLowerCase('es'),state=$('state').value,risk=$('risk').value;
  const controls=current.controles.filter(c=>(!state||state===c.estado)&&(!risk||risk===c.riesgo)&&(!q||[c.id,c.nombre,c.recomendacion].join(' ').toLocaleLowerCase('es').includes(q)));
  $('count').textContent=controls.length+' de '+current.controles.length+' controles';
  const elements=controls.map(c=>{
    const details=document.createElement('details');details.className='control';
    const sum=document.createElement('summary');sum.append(text('span',c.id,'control-id'),text('span',c.nombre,'control-title'),status(c),text('span',c.riesgo,'risk'));
    const body=text('div','','control-body');body.append(field('Valor actual',value(c.actual)),field('Valor recomendado',c.esperado),field('Por qué importa',c.explicacion),field('Qué puede romper',c.efectos_secundarios),field('Recomendación concreta',c.recomendacion,'wide'));
    if(c.error)body.append(field('Información de evaluación',c.error,'wide'));
    const technical=text('div','','wide technical-info');technical.hidden=!$('technical').checked;technical.append(field('Justificación',c.justificacion),field('Aplicabilidad',c.aplicabilidad));
    try{const u=new URL(c.fuente);if(u.protocol==='https:'){const a=text('a','Fuente de referencia ↗');a.href=u.href;a.target='_blank';a.rel='noopener noreferrer';technical.append(a);}else technical.append(text('p',c.fuente));}catch{technical.append(text('p',c.fuente));}
    body.append(technical);details.append(sum,body);return details;
  });
  $('controls').replaceChildren(...(elements.length?elements:[text('p','No hay controles que coincidan con esos filtros.','empty')]));
}
async function selected(file){try{const d=await read(file);load(d,file.name);}catch(e){message(e.message,true);}}
$('file').addEventListener('change',e=>selected(e.target.files[0]));
$('example').addEventListener('click',()=>{try{load(structuredClone(window.BASELINE_EXAMPLE),'ejemplo real incorporado');}catch(e){message(e.message,true);}});
for(const name of ['dragenter','dragover'])$('dropzone').addEventListener(name,e=>{e.preventDefault();$('dropzone').classList.add('dragging');});
for(const name of ['dragleave','drop'])$('dropzone').addEventListener(name,e=>{e.preventDefault();$('dropzone').classList.remove('dragging');});
$('dropzone').addEventListener('drop',e=>{if(e.dataTransfer.files.length!==1){message('Arrastra un solo JSON para el resumen.',true);return;}selected(e.dataTransfer.files[0]);});
for(const id of ['search','state','risk','technical'])$(id).addEventListener('input',renderControls);
$('clear').addEventListener('click',()=>{for(const id of ['search','state','risk'])$(id).value='';renderControls();});
$('theme').addEventListener('click',()=>{const dark=document.body.classList.toggle('dark');$('theme').textContent=dark?'Modo claro':'Modo oscuro';$('theme').setAttribute('aria-pressed',String(dark));});
function download(data,name){const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json;charset=utf-8'}));const a=text('a','');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
$('export').addEventListener('click',()=>{if(current)download(current,'baseline-'+current.etapa+'.json');});
$('print').addEventListener('click',()=>window.print());
let printStates=[];window.addEventListener('beforeprint',()=>{printStates=[...document.querySelectorAll('details')].map(e=>[e,e.open]);for(const [e] of printStates)e.open=true;});window.addEventListener('afterprint',()=>{for(const [e,v] of printStates)e.open=v;});
for(const id of ['before','after'])$(id).addEventListener('change',async e=>{
  try{const d=await read(e.target.files[0]);if(id==='before')before=d;else after=d;$(id+'-name').textContent=e.target.files[0].name;renderComparison();}
  catch(err){if(id==='before')before=null;else after=null;$(id+'-name').textContent='Archivo no válido';$('comparison').replaceChildren();message(err.message,true,'compare-message');}
});
function renderComparison(){
  $('comparison').replaceChildren();if(!before||!after){message('Falta '+(!before?'auditoría inicial':'auditoría posterior')+'.',false,'compare-message');return;}
  try{
    const c=M.compare(before,after);
    message('Confirma que ambos archivos proceden de la misma VM. El contrato público omite identificadores personales del equipo.',false,'compare-message');
    const grid=text('div','','delta-grid');
    for(const [label,val] of [['Incremento',c.delta===null?'Indeterminado':(c.delta>0?'+':'')+c.delta+' pp'],['Mejoraron',c.rows.filter(r=>r.cambio==='Mejoró').length],['Empeoraron',c.rows.filter(r=>r.cambio==='Empeoró').length],['No comparables',c.rows.filter(r=>r.cambio==='No comparable').length]]){const card=text('div','','card');card.append(text('strong',val),text('span',label));grid.append(card);}
    const chart=text('div','','bar-chart');for(const [label,s] of [['Antes',c.antes],['Después',c.despues]]){const row=text('div','','bar-line');const meter=document.createElement('meter');meter.min=0;meter.max=100;meter.value=s.porcentaje_cumplimiento||0;meter.setAttribute('aria-label',label+' '+pct(s.porcentaje_cumplimiento));row.append(text('strong',label),meter,text('span',pct(s.porcentaje_cumplimiento)));chart.append(row);}
    const note=text('p','Denominadores: '+c.antes.evaluados+' antes y '+c.despues.evaluados+' después. Comparables en ambos: '+c.denominador_comun+'; cambio sobre ese conjunto fijo: '+(c.delta_comun===null?'indeterminado':c.delta_comun+' pp')+'. «Igual» significa mismo estado de cumplimiento.','muted');
    const wrap=text('div','','comparison-scroll'),table=document.createElement('table'),head=document.createElement('thead'),hr=document.createElement('tr');for(const h of ['ID','Control','Antes','Después','Cambio']){const th=text('th',h);th.scope='col';hr.append(th);}head.append(hr);table.append(head);const tbody=document.createElement('tbody');for(const r of c.rows){const tr=document.createElement('tr');for(const k of ['id','nombre','antes','despues','cambio'])tr.append(text('td',r[k]));tbody.append(tr);}table.append(tbody);wrap.append(table);
    const exp=text('button','Descargar comparación');exp.type='button';exp.addEventListener('click',()=>download(c,'comparacion-baseline.json'));
    $('comparison').append(grid,chart,note,exp,wrap);
  }catch(e){message(e.message,true,'compare-message');}
}
