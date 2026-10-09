// Sooda — phone verification via Twilio SMS / WhatsApp.
let cooldownTimer;

function showErr(msg) {
  const e = document.getElementById('form-err');
  e.textContent = msg;
  e.style.display = 'block';
}
function hideErr() {
  document.getElementById('form-err').style.display = 'none';
}
function startCooldown() {
  let s = 60;
  const btn = document.getElementById('resend');
  const cd = document.getElementById('cd');
  btn.disabled = true;
  clearInterval(cooldownTimer);
  cooldownTimer = setInterval(() => {
    s -= 1;
    if (s <= 0) {
      clearInterval(cooldownTimer);
      btn.disabled = false;
      btn.innerHTML = 'Resend code';
    } else {
      cd.textContent = s;
    }
  }, 1000);
}

let lastChannel = 'sms';

async function requestCode(channel) {
  hideErr();
  lastChannel = channel;
  try {
    const r = await api.post('/api/auth/phone/request', { channel });
    document.getElementById('step-channel').style.display = 'none';
    document.getElementById('step-code').style.display = '';
    document.getElementById('sent-to').textContent =
      `Code sent via ${channel === 'whatsapp' ? 'WhatsApp' : 'SMS'}.`;
    startCooldown();
    if (r.test_code) toast('Test mode — code: ' + r.test_code);
  } catch (err) {
    showErr(err.message);
  }
}

async function init() {
  await boot();
  if (!currentUser) {
    location.href = '/login.html?next=/verify-phone.html';
    return;
  }
  if (currentUser.phone_verified) {
    location.href = '/';
    return;
  }
  document.getElementById('verify-sub').textContent =
    `We'll send a 6-digit code to ${currentUser.phone}.`;

  document.getElementById('btn-sms').addEventListener('click', () => requestCode('sms'));
  document.getElementById('btn-wa').addEventListener('click', () => requestCode('whatsapp'));
  document.getElementById('resend').addEventListener('click', () => requestCode(lastChannel));

  document.getElementById('code-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    hideErr();
    try {
      const { user } = await api.post('/api/auth/phone/verify', {
        code: document.getElementById('code').value,
      });
      currentUser = user;
      document.getElementById('step-code').style.display = 'none';
      document.getElementById('step-done').style.display = '';
      toast('Phone verified');
    } catch (err) {
      showErr(err.message);
    }
  });
}

init();
