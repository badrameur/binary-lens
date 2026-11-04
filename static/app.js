'use strict';
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const state = {file: null, result: null, busy: false};
const bytes = (n) => n < 1024 ? `${n} B` : n < 1024 ** 2 ? `${(n / 1024).toFixed(1)} KiB` : `${(n / 1024 ** 2).toFixed(2)} MiB`;
const num = (n) => Number.isInteger(n) ? n.toLocaleString() : Number(n).toPrecision(5);
const signed = (n) => `${n >= 0 ? '+' : ''}${n.toFixed(4)}`;
function node(tag, text, className) {const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (className) e.className = className; return e;}
function hide(selector, yes = true) {$(selector).classList.toggle('hidden', yes);}
function error(message) {$('#error').textContent = message; hide('#error', !message);}
function list(selector, items, empty = 'None found in the inspected data.') {const e = $(selector); e.replaceChildren(...(items.length ? items : [empty]).map(x => node('li', x)));}
function cells(parent, values) {const row = node('tr'); for (const value of values) row.append(node('td', String(value))); parent.append(row);}

$$('[data-page]').forEach(button => button.addEventListener('click', () => {
  $$('[data-page]').forEach(b => b.classList.toggle('active', b === button));
  $$('.page').forEach(p => p.classList.toggle('hidden', p.id !== `page-${button.dataset.page}`));
  $('#page-name').textContent = {analyze: 'File analyzer', learn: 'How the AI works', evaluation: 'Model evaluation'}[button.dataset.page];
  if (button.dataset.page === 'analyze') requestAnimationFrame(drawCharts);
  if (button.dataset.page === 'evaluation') refreshStatus();
}));
$$('[data-tab]').forEach(button => button.addEventListener('click', () => {
  $$('[data-tab]').forEach(b => {b.classList.toggle('active', b === button); b.setAttribute('aria-selected', String(b === button));});
  $$('.tab-content').forEach(p => p.classList.toggle('hidden', p.id !== `tab-${button.dataset.tab}`));
  requestAnimationFrame(drawCharts);
}));
$('#choose-file').addEventListener('click', () => $('#file-input').click());
$('#file-input').addEventListener('change', e => setFile(e.target.files[0]));
function setFile(file) {
  if (!file || state.busy) return false;
  if (file.size > 20 * 1024 * 1024) {error('This file exceeds 20 MiB. Please choose a smaller file.'); return false;}
  if (!file.size) {error('The file is empty. Please choose another file.'); return false;}
  state.file = file; error('');
  $('#file-title').textContent = file.name;
  $('#file-description').textContent = `${bytes(file.size)} · ready for static analysis`;
  $('#choose-file').textContent = 'Change file';
  hide('#scan-file', false);
  return true;
}
for (const type of ['dragenter', 'dragover']) $('#drop-zone').addEventListener(type, e => {e.preventDefault(); if (!state.busy) $('#drop-zone').classList.add('dragover');});
for (const type of ['dragleave', 'drop']) $('#drop-zone').addEventListener(type, e => {e.preventDefault(); $('#drop-zone').classList.remove('dragover');});
$('#drop-zone').addEventListener('drop', e => setFile(e.dataTransfer.files[0]));
$('#scan-file').addEventListener('click', scan);
$('#demo-file').addEventListener('click', async () => {
  if (state.busy) return;
  try {const response = await fetch('/api/demo'); if (!response.ok) throw Error('Demo sample is unavailable. Choose a file from your computer.');
    if (setFile(new File([await response.blob()], 'system-true.elf'))) await scan();
  } catch (e) {error(e.message);}
});
async function scan() {
  if (!state.file || state.busy) return;
  state.busy = true; error(''); hide('#progress', false); hide('#results');
  ['#choose-file', '#scan-file', '#demo-file', '#model-choice'].forEach(s => $(s).disabled = true);
  const start = Date.now(); $('#elapsed').textContent = '0s';
  const timer = setInterval(() => {$('#elapsed').textContent = `${Math.floor((Date.now() - start) / 1000)}s`;}, 1000);
  try {
    const form = new FormData(); form.append('file', state.file); form.append('model_variant', $('#model-choice').value);
    const response = await fetch('/api/analyze', {method: 'POST', body: form});
    const result = await response.json();
    if (!response.ok) throw Error(typeof result.detail === 'string' ? result.detail : 'The file could not be analyzed.');
    state.result = result; renderResult(result); hide('#empty-state'); hide('#results', false);
    requestAnimationFrame(drawCharts);
  } catch (e) {error(e.message || 'Connection failed. Check that the Python server is running.');}
  finally {clearInterval(timer); hide('#progress'); state.busy = false; ['#choose-file', '#scan-file', '#demo-file', '#model-choice'].forEach(s => $(s).disabled = false);}
}

function renderResult(r) {
  const p = r.prediction, s = r.structure;
  $('#result-name').textContent = r.filename; $('#result-format').textContent = s.format;
  $('#analysis-time').textContent = `${r.elapsed_seconds.toFixed(2)}s`;
  $('#verdict').textContent = p.available ? {likely_benign:'Likely benign', likely_malicious:'Likely malicious', uncertain:'Uncertain'}[p.verdict] : 'Prediction unavailable';
  const panel = $('.verdict-panel'); panel.classList.toggle('malicious', p.verdict === 'likely_malicious'); panel.classList.toggle('uncertain', !p.available || p.verdict === 'uncertain');
  $('#score').textContent = p.available ? p.score.toPrecision(4) : '—';
  $('#score-marker').style.left = `${p.available ? p.score * 100 : 50}%`;
  $('#prediction-note').textContent = p.available ? 'Demo thresholds: ≤ 0.2 likely benign · ≥ 0.8 likely malicious. A low score cannot establish safety.' : p.error;
  const identity = $('#identity'); identity.replaceChildren();
  for (const [label, value] of [['Category', s.category], ['Architecture', s.architecture], ['File size', bytes(r.size)], ['Entropy', `${r.entropy.toFixed(3)} / 8`], ['Entry point', s.entry_point || 'Not available'], ['Model', p.available ? p.model : 'Not applied']]) identity.append(node('dt', label), node('dd', value));
  $('#sha256').textContent = r.sha256;
  $('#finding-count').textContent = r.findings.length;
  renderExplanation(p); renderStructure(s);
  const findings = $('#observations'); findings.replaceChildren();
  if (!r.findings.length) findings.append(node('p', 'No indicators from the implemented structural checks. This does not establish safety.', 'muted'));
  for (const f of r.findings) {const e = node('article', undefined, 'finding'); e.append(node('h3', f.title), node('p', f.detail)); findings.append(e);}
  list('#embedded', r.embedded_signatures.map(x => `${x.type} signature at byte ${x.offset.toLocaleString()}`));
  list('#warnings', s.warnings, 'No parser warnings reported.');
  $('#string-rows').replaceChildren(); r.strings.forEach(x => cells($('#string-rows'), [`0x${x.offset.toString(16)}`, x.text]));
}
function renderExplanation(p) {
  const container = $('#group-contributions'); container.replaceChildren();
  $('#tree-path').replaceChildren(); $('#feature-rows').replaceChildren();
  if (!p.available) {
    container.append(node('p', p.error, 'muted')); $('#model-summary').textContent = 'Basic byte inspection is still available. No malware conclusion is made.';
    $('#model-equation').textContent = 'No prediction → no model attribution'; $('#model-dimensions').textContent = ''; return;
  }
  const max = Math.max(...p.groups.map(g => Math.abs(g.contribution)), 0.00001);
  for (const g of p.groups.filter(g => Math.abs(g.contribution) > 0.000001)) {
    const row = node('div', undefined, 'contrib-row'); const track = node('div', undefined, 'contrib-track');
    const bar = node('span', undefined, `contrib-bar ${g.contribution >= 0 ? 'positive' : 'negative'}`); bar.style.width = `${Math.abs(g.contribution) / max * 49}%`;
    track.append(bar); row.append(node('span', g.name), track, node('span', signed(g.contribution), `contrib-value ${g.contribution >= 0 ? 'positive-text' : 'negative-text'}`)); container.append(row);
  }
  $('#model-summary').textContent = p.summary;
  $('#model-equation').textContent = `Baseline ${p.baseline.toFixed(4)} + contributions (${signed(p.contribution_sum)}) = raw score ${p.raw_score.toFixed(4)} → sigmoid → ${p.score.toPrecision(4)}`;
  $('#model-dimensions').textContent = `${p.trees.toLocaleString()} TREES · ${p.features.toLocaleString()} FEATURES`;
  for (const step of p.first_tree.steps) {
    const li = node('li', `${step.feature} ${step.operator} ${typeof step.threshold === 'number' ? num(step.threshold) : step.threshold}`);
    li.append(node('small', `Measured: ${num(step.value)} · followed ${step.branch} branch`)); $('#tree-path').append(li);
  }
  $('#tree-path').append(node('li', `Reached leaf ${p.first_tree.leaf_index} · raw tree contribution ${signed(p.first_tree.leaf_value)}`));
  p.top_features.forEach(f => cells($('#feature-rows'), [f.name, num(f.value), signed(f.contribution)]));
}
function renderStructure(s) {
  $('#section-rows').replaceChildren();
  const regions = [...s.sections, ...s.segments, ...(s.trailing ? [s.trailing] : [])];
  regions.forEach(r => cells($('#section-rows'), [`${r.name}${r.kind === 'segment' ? ' [segment]' : ''}`, `0x${r.offset.toString(16)}`, r.no_file_bytes ? `0 B (${bytes(r.memory_size)} in memory)` : bytes(r.size), r.permissions || '—', r.entropy.toFixed(3)]));
  if (!regions.length) cells($('#section-rows'), ['No supported section or segment structure', '—', '—', '—', '—']);
  list('#imports', s.imports, 'No imports available (or file is statically linked / unsupported).');
  list('#exports', [...s.exports, ...s.resources.map(x => `Resource type: ${x}`)]);
}

function canvasContext(selector, height) {
  const canvas = $(selector); if (!canvas || !canvas.getBoundingClientRect().width) return null;
  const width = canvas.getBoundingClientRect().width; const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.round(width * dpr); canvas.height = Math.round(height * dpr); canvas.style.height = `${height}px`;
  const ctx = canvas.getContext('2d'); ctx.scale(dpr, dpr); ctx.font = '10px ui-monospace, monospace';
  return {canvas, ctx, w: width, h: height};
}
function drawCharts() {
  if (!state.result) return;
  drawEntropy(); drawHistogram(); drawByteImage(); drawLayout();
}
function drawEntropy() {
  const c = canvasContext('#entropy-chart', 210); if (!c) return;
  const {ctx,w,h,canvas} = c; const values = state.result.visuals.entropy_windows; const left = 32, top = 15, right = w - 12, bottom = h - 28;
  ctx.strokeStyle = '#2c3f47'; ctx.fillStyle = '#78939d';
  for (let value = 0; value <= 8; value += 2) {const y = bottom - value / 8 * (bottom - top); ctx.beginPath(); ctx.moveTo(left,y); ctx.lineTo(right,y); ctx.stroke(); ctx.fillText(String(value), 8, y + 3);}
  const xy = values.map((x,i) => [left + (i + .5) / values.length * (right-left), bottom - x.entropy / 8 * (bottom-top)]);
  ctx.beginPath(); ctx.moveTo(left, bottom); xy.forEach(([x,y]) => ctx.lineTo(x,y)); ctx.lineTo(right,bottom); ctx.closePath();
  const gradient = ctx.createLinearGradient(0,top,0,bottom); gradient.addColorStop(0,'#63d8c640'); gradient.addColorStop(1,'#63d8c604'); ctx.fillStyle = gradient; ctx.fill();
  ctx.beginPath(); xy.forEach(([x,y],i) => i ? ctx.lineTo(x,y) : ctx.moveTo(x,y)); ctx.strokeStyle='#63d8c6'; ctx.lineWidth=1.6; ctx.stroke();
  ctx.fillStyle='#78939d'; ctx.fillText('0 B',left,h-7); const label=bytes(state.result.size); ctx.fillText(label,right-ctx.measureText(label).width,h-7);
  canvas.onmousemove = e => {const rect=canvas.getBoundingClientRect(); const i=Math.max(0,Math.min(values.length-1,Math.floor((e.clientX-rect.left-left)/(right-left)*values.length))); const v=values[i]; $('#entropy-hover').textContent=`Offset ${v.offset.toLocaleString()} · ${bytes(v.size)} window · entropy ${v.entropy.toFixed(3)} / 8`;};
}
function drawHistogram() {
  const c=canvasContext('#histogram-chart',220); if (!c) return; const {ctx,w,h}=c; const values=state.result.visuals.histogram; const max=Math.max(...values,1); const left=15, bottom=h-28;
  values.forEach((n,i)=>{ctx.fillStyle=i%32===0?'#b7f399':'#5a9b94';const bar=n/max*(h-45);ctx.fillRect(left+i/256*(w-left-10),bottom-bar,Math.max(1,(w-left-10)/256),bar);});
  ctx.fillStyle='#78939d'; ctx.fillText('0x00',left,h-6);ctx.fillText('0xFF',w-36,h-6);ctx.fillText(`max ${max.toLocaleString()} occurrences`,left,10);
}
function drawByteImage() {
  const canvas=$('#byte-image'); const image=state.result.visuals.byte_image;
  const values=Uint8Array.from(atob(image.pixels), c=>c.charCodeAt(0)); const height=Math.ceil(values.length/image.width);
  canvas.width=image.width;canvas.height=height;const ctx=canvas.getContext('2d');const out=ctx.createImageData(image.width,height);
  for(let i=0;i<image.width*height;i++){out.data[i*4]=values[i]||0;out.data[i*4+1]=values[i]||0;out.data[i*4+2]=values[i]||0;out.data[i*4+3]=255;}ctx.putImageData(out,0,0);
}
function drawLayout() {
  const c=canvasContext('#layout-chart',110); if(!c)return;const {ctx,w}=c;const s=state.result.structure;const colors=['#63d8c6','#90be87','#6fa6ce','#bd9ad0','#d2b273','#6d8992'];
  const rows=[s.sections,s.segments]; const legend=$('#layout-legend');legend.replaceChildren();
  rows.forEach((regions,row)=>{const y=20+row*36;ctx.fillStyle='#20323b';ctx.fillRect(0,y,w,23);
    regions.forEach((r,i)=>{const x=Math.max(0,r.offset/state.result.size*w);const width=Math.min(w-x,r.size/state.result.size*w);ctx.fillStyle=colors[i%colors.length];if(width>0)ctx.fillRect(x,y,Math.max(1,width),23);});
    ctx.fillStyle='#78939d';ctx.fillText(row?'Segments':'Sections',0,y-6);
  });
  s.sections.slice(0,8).forEach((r,i)=>{const item=node('span');const dot=node('i');dot.style.background=colors[i%colors.length];item.append(dot,document.createTextNode(r.name));legend.append(item);});
  if(s.trailing){ctx.fillStyle='#fa8c8c';ctx.fillRect(s.trailing.offset/state.result.size*w,92,s.trailing.size/state.result.size*w,7);}
}
window.addEventListener('resize',()=>requestAnimationFrame(drawCharts));
$('#download-report').addEventListener('click',()=>{if(!state.result)return;const url=URL.createObjectURL(new Blob([JSON.stringify(state.result,null,2)],{type:'application/json'}));const a=node('a');a.href=url;a.download=`binary-lens-${state.result.sha256.slice(0,12)}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});

async function refreshStatus(){
  try{const response=await fetch('/api/status');if(!response.ok)throw Error();const s=await response.json();
    $('#model-status').replaceChildren(node('span',undefined,'status-dot'),document.createTextNode(s.models.PE&&s.models.ELF?'Windows + Linux models ready':'Models incomplete'));
    renderEvaluation(s.evaluation);
  }catch{$('#model-status').textContent='Server unavailable';}
}
function renderEvaluation(e){
  const content=$('#evaluation-content');content.replaceChildren();
  if(!e){const panel=node('article',undefined,'panel');panel.append(node('h2','Evaluation has not been run yet'),node('p','Run the included evaluation script on labeled benchmark features. No performance figures are claimed until measured.'));content.append(panel);return;}
  const intro=node('article',undefined,'panel');intro.append(node('h2',e.title||'Linux ELF benchmark'),node('p',e.description||''),node('p',`Dataset: ${e.dataset} · Test samples: ${e.test_samples.toLocaleString()} · Decision threshold: ${e.threshold}`,'footnote'));content.append(intro);
  for(const result of e.models){const panel=node('article',undefined,'panel');panel.append(node('h2',result.name),node('p',result.description||'','muted'));
    const grid=node('div',undefined,'metric-grid');for(const [label,key]of[['Precision','precision'],['Recall','recall'],['False-positive rate','false_positive_rate'],['Accuracy','accuracy']]){const box=node('div',undefined,'metric-box');box.append(node('strong',`${(result[key]*100).toFixed(2)}%`),node('span',label));grid.append(box);}panel.append(grid);
    const table=node('table',undefined,'matrix');const head=node('thead');const hr=node('tr');for(const v of ['Actual / predicted','Benign','Malicious'])hr.append(node('th',v));head.append(hr);table.append(head);const body=node('tbody');cells(body,['Benign',result.tn,result.fp]);cells(body,['Malicious',result.fn,result.tp]);table.append(body);panel.append(table);
    if(result.training_samples!==undefined)panel.append(node('p',`Training examples: ${result.training_samples.toLocaleString()} · Training time: ${result.training_seconds.toFixed(2)}s`,'footnote'));content.append(panel);
  }
  const note=node('article',undefined,'panel');note.append(node('h2','Scope of this experiment'),node('p',e.limitations));content.append(note);
}
refreshStatus();
