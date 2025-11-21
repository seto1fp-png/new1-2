const API = ''; // إذا كان الـ backend على دومين مختلف، ضع رابطه هنا مثل: https://short.example.com

function el(id) { return document.getElementById(id); }

// عناصر الواجهة
const urlInput       = el('urlInput');
const shortenBtn     = el('shortenBtn');
const copyBtn        = el('copyBtn');
const resultBox      = el('result');
const linksList      = el('linksList');
const codeInput      = el('codeInput');
const analyticsBox   = el('analytics');
const adminKeyInput  = el('adminKey');

// أقسام الواجهة
const heroSection      = el('hero');
const analyticsPanel   = el('analyticsPanel');
const loginPanel       = el('loginPanel');
const listPanel        = el('listPanel');

// روابط التنقل
const toShorten    = el('toShorten');
const toAnalytics  = el('toAnalytics');
const toLogin      = el('toLogin');

// حالة بسيطة لمفتاح الإدارة (على المتصفح فقط)
const ADMIN_KEY_STORAGE = 'shortlink_admin_key';

// ====== وظائف واجهة ======

function showSection(target) {
  const sections = [heroSection, analyticsPanel, loginPanel, listPanel];
  sections.forEach(sec => sec.classList.add('hidden'));
  target.classList.remove('hidden');
}

function setResult(text, shortUrl) {
  if (!text && !shortUrl) {
    resultBox.classList.add('hidden');
    return;
  }
  resultBox.classList.remove('hidden');
  resultBox.innerHTML = `
    <div class="result-title">تم إنشاء الرابط المختصر ✅</div>
    <div class="result-url">${shortUrl ? `<a href="${shortUrl}" target="_blank">${shortUrl}</a>` : text}</div>
  `;
}

// ====== استدعاءات API ======

async function shorten() {
  const url = (urlInput.value || '').trim();
  if (!url) return alert('أدخل رابط صالح');

  shortenBtn.disabled = true;
  shortenBtn.textContent = 'جاري الاختصار...';

  try {
    const resp = await fetch((API || '') + '/api/shorten', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    if (!resp.ok) {
      throw new Error('HTTP ' + resp.status);
    }

    const data = await resp.json();
    // نفترض أن الـ backend يرجع: { short, code }
    const base = window.location.origin;
    const shortUrl = data.short || (base + '/' + data.code);

    setResult('', shortUrl);
    copyBtn.dataset.value = shortUrl;
    copyBtn.classList.remove('hidden');

    // حدث قائمة آخر الروابط
    loadLinks();
  } catch (e) {
    console.error(e);
    alert('فشل إنشاء الرابط المختصر');
  } finally {
    shortenBtn.disabled = false;
    shortenBtn.textContent = 'اختصار';
  }
}

async function loadLinks() {
  try {
    const headers = {};
    const savedKey = localStorage.getItem(ADMIN_KEY_STORAGE);
    if (savedKey) headers['x-admin-key'] = savedKey;

    const resp = await fetch((API || '') + '/api/links', { headers });
    if (!resp.ok) return;

    const data = await resp.json();
    renderLinks(data || []);
  } catch (e) {
    console.warn('links load error', e);
  }
}

function renderLinks(items) {
  if (!Array.isArray(items) || !items.length) {
    linksList.innerHTML = '<div class="muted empty">لا توجد روابط بعد.</div>';
    return;
  }

  const base = window.location.origin;
  linksList.innerHTML = items
    .map(item => {
      const code = item.code || '';
      const shortUrl = item.short || (base + '/' + code);
      return `
        <div class="item">
          <div class="item-main">
            <a href="${shortUrl}" target="_blank" class="item-short">${shortUrl}</a>
            <div class="item-original" title="${item.original || ''}">
              ${item.original || ''}
            </div>
          </div>
          <div class="item-meta">
            <span>زيارات: <strong>${item.hits || 0}</strong></span>
            ${code ? `<button class="tiny" data-analytics-code="${code}">تحليلات</button>` : ''}
          </div>
        </div>
      `;
    })
    .join('');

  // ربط أزرار التحليلات في القائمة
  linksList.querySelectorAll('[data-analytics-code]').forEach(btn => {
    btn.addEventListener('click', () => {
      const c = btn.getAttribute('data-analytics-code');
      codeInput.value = c;
      showSection(analyticsPanel);
      fetchAnalytics();
    });
  });
}

async function fetchAnalytics() {
  let code = (codeInput.value || '').trim();
  if (!code) return alert('أدخل الكود أو الرابط المختصر');

  // السماح بلصق الرابط نفسه واستخراج الكود
  try {
    const url = new URL(code);
    const path = url.pathname.replace(/^\//, '');
    if (path) code = path;
  } catch (_) {
    // ليست URL، نعتبرها كود فقط
  }

  analyticsBox.innerHTML = '<div class="muted">جاري جلب البيانات...</div>';

  try {
    const resp = await fetch((API || '') + '/api/analytics/' + encodeURIComponent(code));
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const data = await resp.json();
    analyticsBox.innerHTML = formatAnalytics(data);
  } catch (e) {
    console.error(e);
    analyticsBox.innerHTML = '<div class="error">فشل جلب التحليلات لهذا الكود.</div>';
  }
}

function formatAnalytics(d) {
  if (!d || !d.total) {
    return '<div class="muted">لا توجد بيانات لهذا الكود حتى الآن.</div>';
  }

  const block = (title, obj) => {
    const entries = Object.entries(obj || {});
    if (!entries.length) return '';
    return `
      <div class="analytics-block">
        <div class="analytics-title">${title}</div>
        <div class="analytics-tags">
          ${entries
            .map(([k, v]) => `<span class="tag">${k} <span class="tag-count">${v}</span></span>`)
            .join('')}
        </div>
      </div>
    `;
  };

  return `
    <div class="analytics-summary">
      <div class="analytics-number">${d.total}</div>
      <div class="analytics-label">إجمالي الزيارات</div>
    </div>
    ${block('الدول', d.byCountry)}
    ${block('الأجهزة', d.byDevice)}
    ${block('المتصفحات', d.byBrowser)}
  `;
}

// ====== تسجيل دخول بسيط (على المتصفح فقط) ======

function initAdminFromStorage() {
  const savedKey = localStorage.getItem(ADMIN_KEY_STORAGE);
  if (savedKey) {
    adminKeyInput.value = savedKey;
    loginPanel.classList.add('logged');
  }
}

function adminLogin() {
  const key = (adminKeyInput.value || '').trim();
  if (!key) {
    alert('أدخل مفتاح الإدارة');
    return;
  }
  localStorage.setItem(ADMIN_KEY_STORAGE, key);
  loginPanel.classList.add('logged');
  alert('تم حفظ مفتاح الإدارة على هذا المتصفح فقط');
  loadLinks();
}

// ====== نسخ الرابط المختصر ======

async function copyShort() {
  const value = copyBtn.dataset.value;
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    copyBtn.textContent = 'تم النسخ ✔';
    setTimeout(() => (copyBtn.textContent = 'نسخ الرابط'), 1200);
  } catch (e) {
    console.warn(e);
    alert('تعذر النسخ، انسخ الرابط يدويًا.');
  }
}

// ====== ربط الأحداث عند تحميل الصفحة ======

document.addEventListener('DOMContentLoaded', () => {
  // تنقّل بين الأقسام
  if (toShorten) {
    toShorten.addEventListener('click', () => showSection(heroSection));
  }
  if (toAnalytics) {
    toAnalytics.addEventListener('click', () => showSection(analyticsPanel));
  }
  if (toLogin) {
    toLogin.addEventListener('click', () => showSection(loginPanel));
  }

  // أزرار أساسية
  shortenBtn && shortenBtn.addEventListener('click', shorten);
  copyBtn && copyBtn.addEventListener('click', copyShort);
  el('fetchAnalytics') && el('fetchAnalytics').addEventListener('click', fetchAnalytics);
  el('adminLogin') && el('adminLogin').addEventListener('click', adminLogin);

  // إدخال Enter في حقل الرابط
  urlInput && urlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') shorten();
  });

  // تهيئة الإدارة و تحميل الروابط
  initAdminFromStorage();
  loadLinks();
});