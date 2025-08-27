// SPA client logic moved from inline template
(function(){
  function showTab(name){
    document.querySelectorAll('.tab').forEach(el=>{
      el.style.display='none';
      el.style.opacity=0;
      el.setAttribute('aria-hidden','true');
    });
    var panel = document.getElementById('tab-'+name);
    if(panel){
      panel.style.display='block';
      setTimeout(()=>{ panel.style.opacity = 1; }, 20);
      panel.setAttribute('aria-hidden','false');
      panel.focus();
    }
    history.replaceState(null,'', '#'+name);
    try{
      document.querySelectorAll('#global-bottom-nav .tab-link').forEach(b=>{ b.classList.remove('active'); b.setAttribute('aria-selected','false'); });
      var btn = document.querySelector('#global-bottom-nav .tab-link[data-tab="'+name+'"]');
      if(btn){ btn.classList.add('active'); btn.setAttribute('aria-selected','true'); }
    }catch(e){ /* ignore */ }
  }

  // keyboard support for tab navigation
  (function(){
    var nav = document.getElementById('global-bottom-nav');
    if(!nav) return;
    nav.addEventListener('keydown', function(e){
      var keys = {37:'left',39:'right',36:'home',35:'end'};
      var key = keys[e.keyCode];
      if(!key) return;
      var tabs = Array.from(nav.querySelectorAll('.tab-link'));
      var idx = tabs.findIndex(t=>t.classList.contains('active'));
      if(idx<0) idx = 0;
      if(key==='left') idx = (idx-1+tabs.length)%tabs.length;
      if(key==='right') idx = (idx+1)%tabs.length;
      if(key==='home') idx = 0;
      if(key==='end') idx = tabs.length-1;
      tabs[idx].focus();
      showTab(tabs[idx].dataset.tab);
      e.preventDefault();
    });
  })();

  var params = new URLSearchParams(window.location.search);
  var urlSt = params.get('st') || params.get('token');
  if(urlSt){
    localStorage.setItem('st', urlSt);
    history.replaceState(null, '', window.location.pathname + window.location.hash);
  }

  function parseInitData(initDataStr){
    var out = {};
    if(!initDataStr) return out;
    initDataStr.split('&').forEach(pair=>{
      var parts = pair.split('=');
      var k = decodeURIComponent(parts[0]||'');
      var v = decodeURIComponent((parts[1]||'').replace(/\+/g, ' '));
      out[k] = v;
    });
    return out;
  }

  async function telegramExchange(){
    try{
      if(!window.Telegram || !window.Telegram.WebApp) return null;
      var initData = window.Telegram.WebApp.initData || '';
      if(!initData) return null;
      var body = parseInitData(initData);
      var res = await fetch('/auth/telegram', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
      if(!res.ok) return null;
      var j = await res.json();
      if(j && j.st){
        localStorage.setItem('st', j.st);
        return j.st;
      }
    }catch(e){ console.warn('Telegram exchange failed', e); }
    return null;
  }

  function loadProjects(){
    fetch('/api/projects').then(r=>r.json()).then(arr=>{
      const el = document.getElementById('projects-list'); el.innerHTML='';
      arr.forEach(p=>{ const d=document.createElement('div'); d.innerHTML=`<h3>${p.title}</h3><p>${p.description}</p><button onclick="join(${p.id})">Прикрепиться</button>`; el.appendChild(d); });
    });
  }

  // join uses real telegram id (tg_id) saved after /api/me
  window.join = async function(id){
    var tg = localStorage.getItem('tg_id');
    var st = localStorage.getItem('st');
    if(!tg && st){
      try{
        var r = await fetch('/api/me?st='+st);
        if(r.ok){
          var j = await r.json();
          if(j && j.telegram_id){
            localStorage.setItem('tg_id', j.telegram_id);
            tg = j.telegram_id;
          }
        }
      }catch(e){}
    }
    if(!tg){ alert('Войдите через Telegram чтобы выполнить действие'); return; }
    fetch(`/api/project/${id}/message`, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({telegram_id:tg, text:'Пользователь через веб UI присоединился'})}).then(()=>alert('Запрос отправлен')).catch(()=>alert('Ошибка отправки'));
  }

  function loadProfile(){
    return new Promise((resolve, reject)=>{
      var el = document.getElementById('profile-block');
      var currentToken = localStorage.getItem('st');
      if(!currentToken){ el.innerHTML = '<a href="/auth/telegram?next=/">Войти через Telegram</a>'; resolve(); return; }
      fetch('/api/me?st='+currentToken).then(r=>r.json()).then(d=>{
        if(d.error){
          try{
            if(window.Telegram && window.Telegram.WebApp && window.Telegram.WebApp.initDataUnsafe && window.Telegram.WebApp.initDataUnsafe.user){
              var u = window.Telegram.WebApp.initDataUnsafe.user;
              var name = (u.first_name||'') + (u.last_name?(' '+u.last_name):'');
              el.innerHTML = `<div class="profile"><div style="width:72px;height:72px;border-radius:999px;background:#efefef"></div><div class="meta"><div class="name">${name||'Пользователь'}</div><div class="id">telegram: ${u.id}</div></div></div>`;
              localStorage.setItem('tg_id', u.id);
            } else {
              var st = localStorage.getItem('st');
              if(st && /^\d+$/.test(st)){
                el.innerHTML = `<div class="profile"><div style="width:72px;height:72px;border-radius:999px;background:#efefef"></div><div class="meta"><div class="name">Пользователь</div><div class="id">telegram: ${st}</div></div></div>`;
                localStorage.setItem('tg_id', st);
              } else {
                el.innerHTML = '<a href="/auth/telegram?next=/">Войти через Telegram</a>';
              }
            }
          }catch(e){ el.innerHTML = '<a href="/auth/telegram?next=/">Войти через Telegram</a>'; }
          resolve(); return;
        }
        var photo = d.photo_url || '';
        var first = d.first_seen ? new Date(d.first_seen).toLocaleString() : '';
        function applyProfile(src){
          el.innerHTML = `<div class="profile">` + (src?`<img src="${src}" alt="avatar">`:`<div style="width:72px;height:72px;border-radius:999px;background:#efefef"></div>`) + `<div class="meta"><div class="name">${d.name || 'Пользователь'}</div><div class="id">telegram: ${d.telegram_id}</div><div class="small">Первый вход: ${first}</div></div></div>`;
          if(d.telegram_id) localStorage.setItem('tg_id', d.telegram_id);
          resolve();
        }
        if(photo){
          var img = new Image();
          var settled = false;
          var to = setTimeout(()=>{ if(!settled){ settled=true; applyProfile('/static/images/avatar.png'); } }, 4000);
          img.onload = function(){ if(!settled){ settled=true; clearTimeout(to); applyProfile(photo); } };
          img.onerror = function(){ if(!settled){ settled=true; clearTimeout(to); applyProfile('/static/images/avatar.png'); } };
          img.src = photo;
        } else {
          applyProfile('/static/images/avatar.png');
        }
      }).catch(()=>{ el.innerHTML = '<div class="small">Не удалось загрузить профиль</div>'; resolve(); });
    });
  }

  window.addEventListener('load', async ()=>{
    var tokenNow = localStorage.getItem('st');
    if(!tokenNow && window.Telegram && window.Telegram.WebApp && (window.Telegram.WebApp.initData || window.Telegram.WebApp.initDataUnsafe)){
      await telegramExchange();
    }
    var hash = location.hash.replace('#','') || 'projects';
    showTab(hash);
    document.querySelectorAll('.tab-link').forEach(btn=>btn.addEventListener('click', function(e){ showTab(this.dataset.tab); }));
    loadProjects();
    await runSplashLoad();
  });
  async function runSplashLoad(){
    var bar = document.getElementById('splash-bar');
    var pct = document.getElementById('splash-percent');
    var start = Date.now();
    bar.style.width = '25%'; pct.innerText = '25%';
    try{
      await loadProfile();
      bar.style.width = '75%'; pct.innerText = '75%';
      await new Promise(r=>setTimeout(r, 600));
      bar.style.width = '100%'; pct.innerText = '100%';
    }catch(e){
      bar.style.width = '100%'; pct.innerText = '100%';
    }
    var elapsed = Date.now() - start;
    var remain = Math.max(0, 3000 - elapsed);
    await new Promise(r=>setTimeout(r, remain));
    var sp = document.getElementById('splash');
    if(sp) sp.style.display = 'none';
  }
})();
