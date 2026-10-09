// Sooda — post a new ad, or edit an existing one (?id=).
const editId = new URLSearchParams(location.search).get('id');

function showErr(msg) {
  const e = document.getElementById('form-err');
  e.textContent = msg;
  e.style.display = 'block';
}

async function init() {
  await boot();
  if (!currentUser) {
    location.href = '/login.html?next=' + encodeURIComponent(location.pathname + location.search);
    return;
  }
  if (!currentUser.phone_verified) {
    const w = document.getElementById('verify-warn');
    w.innerHTML = 'Please <a href="/verify-phone.html" style="font-weight:700;text-decoration:underline">verify your phone number</a> before posting ads.';
    w.style.display = 'block';
    document.getElementById('submit-btn').disabled = true;
  }

  const categories = await api.get('/api/categories');
  document.getElementById('category').innerHTML =
    categories.map((c) => `<option value="${c.id}">${esc(c.name)}</option>`).join('');
  const locs = await api.get('/api/locations');
  document.getElementById('location').innerHTML =
    locs.map((l) => `<option>${esc(l)}</option>`).join('');

  let existing = null;
  if (editId) {
    try {
      ({ ad: existing } = await api.get('/api/ads/' + editId));
    } catch { showErr('Ad not found.'); return; }
    if (!existing.is_owner) { showErr('You can only edit your own ads.'); return; }
    document.getElementById('form-title').textContent = 'Edit your ad';
    document.getElementById('submit-btn').textContent = 'Save changes';
    document.getElementById('images-field').style.display = 'none';
    document.getElementById('category').value = existing.category.id;
    document.getElementById('location').value = existing.location;
    document.getElementById('title').value = existing.title;
    document.getElementById('description').value = existing.description;
    document.getElementById('price').value = existing.price;
    document.getElementById('condition').value = existing.condition;
    document.getElementById('negotiable').checked = existing.negotiable;
  }

  document.getElementById('images').addEventListener('change', (e) => {
    const prev = document.getElementById('img-preview');
    prev.innerHTML = '';
    [...e.target.files].slice(0, 6).forEach((f) => {
      const img = document.createElement('img');
      img.src = URL.createObjectURL(f);
      prev.appendChild(img);
    });
  });

  document.getElementById('ad-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = document.getElementById('submit-btn');
    btn.disabled = true;
    btn.textContent = 'Saving...';
    try {
      if (existing) {
        await api.put('/api/ads/' + existing.id, {
          category_id: Number(document.getElementById('category').value),
          location: document.getElementById('location').value,
          title: document.getElementById('title').value,
          description: document.getElementById('description').value,
          price: Number(document.getElementById('price').value),
          condition: document.getElementById('condition').value,
          negotiable: document.getElementById('negotiable').checked,
        });
        toast('Ad updated');
        setTimeout(() => location.href = '/ad.html?id=' + existing.id, 800);
      } else {
        const fd = new FormData();
        fd.append('category_id', document.getElementById('category').value);
        fd.append('location', document.getElementById('location').value);
        fd.append('title', document.getElementById('title').value);
        fd.append('description', document.getElementById('description').value);
        fd.append('price', document.getElementById('price').value);
        fd.append('condition', document.getElementById('condition').value);
        fd.append('negotiable',
          document.getElementById('negotiable').checked ? '1' : '0');
        const files = document.getElementById('images').files;
        [...files].slice(0, 6).forEach((f) => fd.append('images', f));
        const r = await fetch('/api/ads', { method: 'POST', body: fd });
        const data = await r.json();
        if (!r.ok) throw new Error(data.error || 'Could not post ad');
        toast('Your ad is live!');
        setTimeout(() => location.href = '/ad.html?id=' + data.id, 800);
      }
    } catch (err) {
      showErr(err.message);
      btn.disabled = false;
      btn.textContent = existing ? 'Save changes' : 'Post ad now';
    }
  });
}

init();
