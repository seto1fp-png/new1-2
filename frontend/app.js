const API = '';// ضع هنا رابط الـ backend إذا نشرته (مثال: https://short.example.com)

function el(id){return document.getElementById(id)}
const urlInput = el('urlInput');
const shortenBtn = el('shortenBtn');
const copyBtn = el('copyBtn');
const result = el('result');
const linksList = el('linksList');

async function shorten(){
  const url = urlInput.value.trim();
  if(!url) return alert('أدخل رابط صالح');
  shortenBtn.disabled = true; shortenBtn.textContent='...';
  try{
    const resp = await fetch((API||'') + '/api/shorten', {
      method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({url})
    });
    if(!resp.ok) throw new Error('failed');
    const data = await resp.json();
    showResult(data);
  }catch(e){ alert('فشل إنشاء الكود. تأكد من تشغيل backend.'); console.error(e); }
  finally{ shortenBtn.disabled=false; shortenBtn.textContent='اختصر الآن'; }
}

function showResult(data){
  result.classList.remove('hidden');
  const short = data.short;
  result.innerHTML = `<div>تم الاختصار: <a href="${short}" target="_blank">${short}</a></div><div class="muted">رمز: <code>${data.code}</code></div>`;
  copyBtn.disabled = false;
  copyBtn.dataset.code = data.code;
}

copyBtn.addEventListener('click', ()=>{
  const code = copyBtn.dataset.code; if(!code) return;
  navigator.clipboard.writeText(code).then(()=>{ copyBtn.textContent='تم النسخ ✓'; setTimeout(()=>copyBtn.textContent='نسخ',1400); });
});
shortenBtn.addEventListener('click', shorten);

// Fetch last links (public)
async function loadLast(){
  try{
    const r = await fetch((API||'') + '/api/links');
    if(!r.ok) return;
    const list = await r.json();
    linksList.innerHTML = list.map(i=>`<div class="item"><a href="${i.short}" target="_blank">${i.short}</a> — <span class="muted">${i.original}</span></div>`).join('');
  }catch(e){console.error(e)}
}
loadLast();

// Analytics fetch
el('fetchAnalytics')?.addEventListener('click', async ()=>{
  const code = el('codeInput').value.trim(); if(!code) return alert('أدخل الكود');
  try{
    const r = await fetch((API||'') + '/api/analytics/' + encodeURIComponent(code));
    if(!r.ok) throw new Error('no');
    const data = await r.json();
    el('analytics').innerHTML = formatAnalytics(data);
  }catch(e){ alert('فشل جلب التحليلات'); }
});

function formatAnalytics(d){
  if(!d || !d.total) return '<div class="muted">لا توجد بيانات.</div>';
  return `<div>الزيارات: <strong>${d.total}</strong></div>
    <div>البلدان: ${Object.entries(d.byCountry||{}).map(([c,n])=>`${c} (${n})`).join(', ')}</div>
    <div>الأجهزة: ${Object.entries(d.byDevice||{}).map(([k,v])=>`${k} (${v})`).join(', ')}</div>
    <div>المتصفحات: ${Object.entries(d.byBrowser||{}).map(([k,v])=>`${k} (${v})`).join(', ')}</div>`;
}
