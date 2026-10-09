// Sooda — login + signup forms (shared script).
function nextUrl() {
  return new URLSearchParams(location.search).get('next') || '/';
}

function showErr(msg) {
  const e = document.getElementById('form-err');
  e.textContent = msg;
  e.style.display = 'block';
}

async function init() {
  await boot();
  if (currentUser) { location.href = nextUrl(); return; }

  const loginForm = document.getElementById('login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('submit-btn');
      btn.disabled = true;
      try {
        await api.post('/api/auth/login', {
          email: document.getElementById('email').value,
          password: document.getElementById('password').value,
        });
        location.href = nextUrl();
      } catch (err) {
        showErr(err.message);
        btn.disabled = false;
      }
    });
  }

  const signupForm = document.getElementById('signup-form');
  if (signupForm) {
    signupForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('submit-btn');
      btn.disabled = true;
      try {
        await api.post('/api/auth/signup', {
          name: document.getElementById('name').value,
          email: document.getElementById('email').value,
          phone: document.getElementById('phone').value,
          password: document.getElementById('password').value,
        });
        toast('Account created — verify your phone to post ads.');
        setTimeout(() => location.href = '/verify-phone.html', 800);
      } catch (err) {
        showErr(err.message);
        btn.disabled = false;
      }
    });
  }
}

init();
