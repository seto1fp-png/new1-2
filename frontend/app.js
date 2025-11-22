const API = ''; // إذا كان الـ backend على دومين مختلف، ضع رابطه هنا مثل: https://short.example.com

function el(id) {
  return document.getElementById(id);
}

const urlInput        = el('urlInput');
const shortenBtn      = el('shortenBtn');
const copyBtn         = el('copyBtn');
const resultBox       = el('result');
const shortUrlDisplay = el('shortUrlDisplay');
const openShortBtn    = el('openShortBtn');

const navShorten    = el('navShorten');
const navDashboard  = el('navDashboard');
const navAnalytics  = el('navAnalytics');

const shortenSection   = el('shortenSection');
const authSection      = el('authSection');
const dashboardSection = el('dashboardSection');
const analyticsSection = el('analyticsSection');

const tabRegister    = el('tabRegister');
const tabLogin       = el('tabLogin');
const registerForm   = el('registerForm');
const loginForm      = el('loginForm');
const registerEmail  = el('registerEmail');
const registerPassword = el('registerPassword');
const loginEmail     = el('loginEmail');
const loginPassword  = el('loginPassword');

const changePasswordForm      = el('changePasswordForm');
const oldPasswordInput        = el('oldPassword');
const newPasswordInput        = el('newPassword');
const newPasswordConfirmInput = el('newPasswordConfirm');

const dashboardUserEmail = el('dashboardUserEmail');
const userLinksList      = el('userLinksList');
const userLinksEmpty     = el('userLinksEmpty');

const codeInput      = el('codeInput');
const fetchAnalyticsBtn = el('fetchAnalytics');
const analyticsBox   = el('analytics');

const currentUserLabel = el('currentUserLabel');
const logoutBtn        = el('logoutBtn');

const yearSpan = el('year');

// مفاتيح التخزين المحلي
const TOKEN_KEY = 'shortlink_token';
const USER_KEY  = 'shortlink_user';
const COPIED_KEY = 'shortlink_copied_links';

let token = localStorage.getItem(TOKEN_KEY) || null;
let currentUser = null;

try {
  const storedUser = localStorage.getItem(USER_KEY);
  if (storedUser) {
    currentUser = JSON.parse(storedUser);
  }
} catch (_) {
  currentUser = null;
}

function saveAuth(newToken, user) {
  token = newToken;
  currentUser = user;
  if (token && user) {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  } else {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  }
  updateAuthUI();
}

function logout() {
  saveAuth(null, null);
}

// دالة عامة للـ fetch تضيف التوكن تلقائياً
async function apiFetch(path, options = {}) {
  const opts = Object.assign({ headers: {} }, options);
  if (!opts.headers['Content-Type'] && !(opts.body instanceof FormData)) {
    opts.headers['Content-Type'] = 'application/json';
  }
  if (token) {
    opts.headers['Authorization'] = 'Bearer ' + token;
  }
  const resp = await fetch((API || '') + path, opts);
  if (resp.status === 401) {
    // صلاحية منتهية أو غير مصرح
    console.warn('Unauthorized, logging out');
    logout();
  }
  return resp;
}

// ----- تنقل الواجهة بين الأقسام -----

function setActiveNav(button) {
  [navShorten, navDashboard, navAnalytics].forEach(btn => {
    if (!btn) return;
    btn.classList.toggle('active', btn === button);
  });
}

function showSection(section) {
  [shortenSection, authSection, dashboardSection, analyticsSection].forEach(sec => {
    if (!sec) return;
    sec.classList.toggle('hidden', sec !== section);
  });
}

function goToShorten() {
  setActiveNav(navShorten);
  showSection(shortenSection);
}

function goToDashboard() {
  setActiveNav(navDashboard);
  if (!currentUser) {
    showSection(authSection);
    showAuthForms();
  } else if (currentUser.must_change_password) {
    showSection(authSection);
    showChangePasswordForm();
  } else {
    showSection(dashboardSection);
    loadUserLinks();
  }
}

function goToAnalytics() {
  setActiveNav(navAnalytics);
  showSection(analyticsSection);
}

// ----- UI للمصادقة -----

function updateAuthUI() {
  const isLoggedIn = !!currentUser;

  if (currentUserLabel) {
    if (isLoggedIn) {
      currentUserLabel.textContent = currentUser.email;
      currentUserLabel.classList.remove('hidden');
    } else {
      currentUserLabel.textContent = '';
      currentUserLabel.classList.add('hidden');
    }
  }

  if (logoutBtn) {
    logoutBtn.classList.toggle('hidden', !isLoggedIn);
  }

  if (dashboardUserEmail) {
    dashboardUserEmail.textContent = isLoggedIn ? currentUser.email : '';
    dashboardUserEmail.classList.toggle('hidden', !isLoggedIn);
  }
}

// تبديل تبويب تسجيل/دخول
function activateAuthTab(tab) {
  if (tab === 'register') {
    tabRegister.classList.add('active');
    tabLogin.classList.remove('active');
    registerForm.classList.remove('hidden');
    loginForm.classList.add('hidden');
    if (changePasswordForm) changePasswordForm.classList.add('hidden');
  } else {
    tabRegister.classList.remove('active');
    tabLogin.classList.add('active');
    registerForm.classList.add('hidden');
    loginForm.classList.remove('hidden');
    if (changePasswordForm) changePasswordForm.classList.add('hidden');
  }
}

function showAuthForms() {
  if (!authSection) return;
  if (tabRegister && tabLogin) {
    tabRegister.classList.remove('hidden');
    tabLogin.classList.remove('hidden');
  }
  if (registerForm) registerForm.classList.remove('hidden');
  if (loginForm) loginForm.classList.add('hidden');
  if (changePasswordForm) changePasswordForm.classList.add('hidden');
  activateAuthTab('register');
}

function showChangePasswordForm() {
  if (!changePasswordForm) return;
  if (tabRegister && tabLogin) {
    tabRegister.classList.add('hidden');
    tabLogin.classList.add('hidden');
  }
  if (registerForm) registerForm.classList.add('hidden');
  if (loginForm) loginForm.classList.add('hidden');
  changePasswordForm.classList.remove('hidden');
}

// ----- عمليات المستخدم العادي -----

async function registerUser(e) {
  e.preventDefault();
  const email = (registerEmail.value || '').trim();
  const password = (registerPassword.value || '').trim();

  if (!email || !password) {
    alert('الرجاء إدخال البريد وكلمة المرور');
    return;
  }

  try {
    const resp = await apiFetch('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.error || 'فشل إنشاء الحساب');
    }
    saveAuth(data.token, data.user);
    alert('تم إنشاء الحساب وتسجيل الدخول بنجاح. الرجاء تغيير كلمة المرور في أول دخول.');
    if (data.user && data.user.must_change_password) {
      showSection(authSection);
      showChangePasswordForm();
    } else {
      goToDashboard();
    }
  } catch (err) {
    console.error(err);
    alert(err.message || 'حدث خطأ أثناء إنشاء الحساب');
  }
}

async function loginUser(e) {
  e.preventDefault();
  const email = (loginEmail.value || '').trim();
  const password = (loginPassword.value || '').trim();

  if (!email || !password) {
    alert('الرجاء إدخال البريد وكلمة المرور');
    return;
  }

  try {
    const resp = await apiFetch('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.error || 'فشل تسجيل الدخول');
    }
    saveAuth(data.token, data.user);
    if (data.user && data.user.must_change_password) {
      alert('هذه أول مرة تسجل الدخول، يجب تغيير كلمة المرور الآن.');
      showSection(authSection);
      showChangePasswordForm();
    } else {
      alert('تم تسجيل الدخول بنجاح');
      goToDashboard();
    }
  } catch (err) {
    console.error(err);
    alert(err.message || 'حدث خطأ أثناء تسجيل الدخول');
  }
}

async function changePassword(e) {
  e.preventDefault();
  const oldPass = (oldPasswordInput.value || '').trim();
  const newPass = (newPasswordInput.value || '').trim();
  const confirm = (newPasswordConfirmInput.value || '').trim();

  if (!oldPass || !newPass || !confirm) {
    alert('الرجاء تعبئة جميع الحقول');
    return;
  }
  if (newPass !== confirm) {
    alert('تأكيد كلمة المرور غير مطابق');
    return;
  }
  if (newPass.length < 6) {
    alert('يفضل أن تكون كلمة المرور 6 أحرف على الأقل');
    return;
  }

  try {
    const resp = await apiFetch('/api/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ oldPassword: oldPass, newPassword: newPass })
    });
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.error || 'فشل تغيير كلمة المرور');
    }
    saveAuth(data.token, data.user);
    alert('تم تغيير كلمة المرور بنجاح');
    goToDashboard();
  } catch (err) {
    console.error(err);
    alert(err.message || 'حدث خطأ أثناء تغيير كلمة المرور');
  }
}

// ----- اختصار الروابط وتخزين الروابط المنسوخة -----

function saveCopiedLink(info) {
  let arr = [];
  try {
    const raw = localStorage.getItem(COPIED_KEY);
    if (raw) arr = JSON.parse(raw);
  } catch (_) {}
  arr.unshift({
    code: info.code,
    short: info.short,
    original: info.original,
    copiedAt: new Date().toISOString()
  });
  arr = arr.slice(0, 50);
  localStorage.setItem(COPIED_KEY, JSON.stringify(arr));
}

async function shorten() {
  const url = (urlInput.value || '').trim();
  if (!url) {
    alert('أدخل رابط صالح');
    return;
  }

  shortenBtn.disabled = true;
  shortenBtn.textContent = 'جاري الاختصار...';

  try {
    const resp = await apiFetch('/api/shorten', {
      method: 'POST',
      body: JSON.stringify({ url })
    });
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.error || 'فشل اختصار الرابط');
    }

    const shortUrl = data.short || (window.location.origin + '/' + data.code);
    shortUrlDisplay.textContent = shortUrl;
    resultBox.classList.remove('hidden');
    copyBtn.disabled = false;

    try {
      await navigator.clipboard.writeText(shortUrl);
      saveCopiedLink({ code: data.code, short: shortUrl, original: data.original });
    } catch (_) {
      // تجاهل خطأ النسخ
    }

    loadUserLinks(); // في حال المستخدم مسجل دخول
  } catch (err) {
    console.error(err);
    alert(err.message || 'حدث خطأ أثناء الاختصار');
  } finally {
    shortenBtn.disabled = false;
    shortenBtn.textContent = 'اختصار الرابط';
  }
}

async function copyShort() {
  const txt = shortUrlDisplay.textContent || '';
  if (!txt) return;
  try {
    await navigator.clipboard.writeText(txt);
    alert('تم نسخ الرابط المختصر');
  } catch (_) {
    alert('تعذر نسخ الرابط تلقائياً، انسخه يدوياً.');
  }
}

// ----- جلب الروابط الخاصة بالمستخدم -----

async function loadUserLinks() {
  if (!currentUser) {
    userLinksList.innerHTML = '';
    userLinksEmpty.classList.remove('hidden');
    return;
  }

  try {
    const resp = await apiFetch('/api/links', { method: 'GET' });
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.error || 'فشل جلب الروابط');
    }
    const links = data.links || [];
    renderUserLinks(links);
  } catch (err) {
    console.error(err);
    userLinksList.innerHTML = '<div class="muted small">تعذر جلب الروابط.</div>';
    userLinksEmpty.classList.add('hidden');
  }
}

function renderUserLinks(links) {
  if (!links.length) {
    userLinksList.innerHTML = '';
    userLinksEmpty.classList.remove('hidden');
    return;
  }

  userLinksEmpty.classList.add('hidden');

  userLinksList.innerHTML = links.map((item) => {
    const shortUrl = (item.code ? window.location.origin + '/' + item.code : '');
    const created = item.created_at ? new Date(item.created_at).toLocaleString('ar-SA') : '';
    return `
      <div class="list-item">
        <div class="item-main">
          <div>الأصلي: <code dir="ltr">${item.original}</code></div>
          <div>المختصر: <code dir="ltr">${shortUrl}</code></div>
          <div class="muted small">${created}</div>
        </div>
        <div class="item-meta">
          <span>زيارات: <strong>${item.hits || 0}</strong></span>
          ${item.code ? `<button class="btn tiny" data-code="${item.code}">تحليلات</button>` : ''}
        </div>
      </div>
    `;
  }).join('');

  userLinksList.querySelectorAll('button[data-code]').forEach(btn => {
    btn.addEventListener('click', () => {
      const c = btn.getAttribute('data-code');
      if (c) {
        codeInput.value = c;
        goToAnalytics();
        fetchAnalytics();
      }
    });
  });
}

// ----- التحليلات -----

function parseCodeFromInput(input) {
  const raw = (input || '').trim();
  if (!raw) return '';
  if (!raw.includes('/')) return raw;
  try {
    const url = new URL(raw);
    let path = url.pathname.replace(/^\//, '');
    if (path.includes('/')) {
      path = path.split('/').filter(Boolean).pop();
    }
    return path;
  } catch (_) {
    return raw;
  }
}

async function fetchAnalytics() {
  const raw = codeInput.value;
  const code = parseCodeFromInput(raw);
  if (!code) {
    alert('أدخل كود أو رابط مختصر');
    return;
  }

  analyticsBox.innerHTML = '<div class="muted small">جاري جلب البيانات...</div>';

  try {
    const resp = await apiFetch('/api/analytics/' + encodeURIComponent(code), { method: 'GET' });
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.error || 'تعذر جلب التحليلات');
    }

    const total = data.total || 0;
    const byCountry = data.byCountry || [];
    const byDevice = data.byDevice || [];
    const byBrowser = data.byBrowser || [];

    const totalHtml = `<div><strong>إجمالي الزيارات:</strong> ${total}</div>`;

    function renderChips(arr) {
      if (!arr.length) return '<span class="muted small">لا توجد بيانات بعد.</span>';
      return '<div class="analytics-chip-row">' + arr.map(item => {
        const label = item.label || item.country || item.device || item.browser || 'غير معروف';
        const count = item.count || 0;
        return `<span class="analytics-chip">${label} — ${count}</span>`;
      }).join('') + '</div>';
    }

    analyticsBox.innerHTML = `
      ${totalHtml}
      <div class="analytics-grid">
        <div class="analytics-card">
          <h3>الدول</h3>
          ${renderChips(byCountry)}
        </div>
        <div class="analytics-card">
          <h3>الأجهزة</h3>
          ${renderChips(byDevice)}
        </div>
        <div class="analytics-card">
          <h3>المتصفحات</h3>
          ${renderChips(byBrowser)}
        </div>
      </div>
    `;
  } catch (err) {
    console.error(err);
    analyticsBox.innerHTML = '<div class="muted small">تعذر جلب التحليلات.</div>';
  }
}

// ----- تهيئة عامة -----

document.addEventListener('DOMContentLoaded', () => {
  if (yearSpan) {
    yearSpan.textContent = new Date().getFullYear();
  }

  updateAuthUI();

  if (navShorten) navShorten.addEventListener('click', goToShorten);
  if (navDashboard) navDashboard.addEventListener('click', goToDashboard);
  if (navAnalytics) navAnalytics.addEventListener('click', goToAnalytics);

  if (tabRegister) tabRegister.addEventListener('click', () => activateAuthTab('register'));
  if (tabLogin) tabLogin.addEventListener('click', () => activateAuthTab('login'));

  if (registerForm) registerForm.addEventListener('submit', registerUser);
  if (loginForm) loginForm.addEventListener('submit', loginUser);
  if (changePasswordForm) changePasswordForm.addEventListener('submit', changePassword);

  if (shortenBtn) shortenBtn.addEventListener('click', shorten);
  if (copyBtn) copyBtn.addEventListener('click', copyShort);
  if (openShortBtn) openShortBtn.addEventListener('click', () => {
    const u = shortUrlDisplay.textContent;
    if (u) window.open(u, '_blank');
  });

  if (fetchAnalyticsBtn) fetchAnalyticsBtn.addEventListener('click', fetchAnalytics);
  if (codeInput) {
    codeInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        fetchAnalytics();
      }
    });
  }

  if (logoutBtn) logoutBtn.addEventListener('click', () => {
    logout();
    goToShorten();
    showAuthForms();
  });

  if (urlInput) {
    urlInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        shorten();
      }
    });
  }

  // إذا كان المستخدم مسجل الدخول مسبقًا وتحتاج كلمة مرور جديدة
  if (currentUser && currentUser.must_change_password) {
    showSection(authSection);
    showChangePasswordForm();
  } else {
    goToShorten();
  }
});
