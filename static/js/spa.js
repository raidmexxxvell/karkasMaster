// SPA client logic moved from inline template
(function(){
  // Initialize socket.io client if available
  try{ if(typeof io === 'function'){ window.socket = io(); window.socket.on('connect', ()=>{ console.log('socket connected'); });
      window.socket.on('activity', function(payload){ try{ var b=document.getElementById('notify-badge'); if(b){ b.style.display='inline-block'; b.textContent = (parseInt(b.textContent||'0')+1).toString(); } }catch(e){} });
      window.socket.on('activity_comment', function(payload){ try{ var b=document.getElementById('notify-badge'); if(b){ b.style.display='inline-block'; b.textContent = (parseInt(b.textContent||'0')+1).toString(); } }catch(e){} });
      window.socket.on('task_created', function(payload){ try{ var b=document.getElementById('notify-badge'); if(b){ b.style.display='inline-block'; b.textContent = (parseInt(b.textContent||'0')+1).toString(); } }catch(e){} });
  }}catch(e){}
  function showTab(name){
    // Slide animation: determine direction from current hash
    var current = location.hash.replace('#','') || 'projects';
    var panels = document.querySelectorAll('.tab');
    panels.forEach(el=>{
      el.classList.remove('enter-left','enter-right','active-slide');
      el.setAttribute('aria-hidden','true');
    });
    var panel = document.getElementById('tab-'+name);
    if(panel){
      // decide enter direction
      var dir = 'right';
      try{ var idxNew = Array.from(document.querySelectorAll('.tab-link')).findIndex(b=>b.dataset.tab===name);
        var idxOld = Array.from(document.querySelectorAll('.tab-link')).findIndex(b=>b.classList.contains('active'));
        if(idxOld>=0 && idxNew>=0){ dir = (idxNew < idxOld)? 'left':'right'; }
      }catch(e){ }
      panel.style.display='block';
      panel.classList.add(dir==='left' ? 'enter-left' : 'enter-right');
      // force reflow then activate
      void panel.offsetWidth;
      panel.classList.add('active-slide');
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
      arr.forEach(p=>{
        const d=document.createElement('div');
        d.className='project-card';
        d.style.padding='12px';
        d.innerHTML = `<div style="display:flex;justify-content:space-between;align-items:center"><div style="flex:1;min-width:0"><h3 style="margin:0">${p.title}</h3><div style="color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${p.description||''}</div></div><div style="margin-left:12px;display:flex;gap:8px"><button data-pid="${p.id}" class="open-project-btn">Открыть</button><button onclick="join(${p.id})">Прикрепиться</button></div></div>`;
        el.appendChild(d);
      });
      document.querySelectorAll('.open-project-btn').forEach(b=>b.addEventListener('click', function(){ loadProjectDetail(parseInt(this.dataset.pid)); }));
    });
  }

  // Render a simple project detail area with activities and tasks
  async function loadProjectDetail(pid){
    // switch to projects tab and scroll to detail
    showTab('projects');
    // Ensure a single project-detail container exists inside the projects tab
    var parent = document.getElementById('projects-list');
    var detailContainer = document.getElementById('project-detail-container');
    if(!detailContainer){
      detailContainer = document.createElement('div');
      detailContainer.id = 'project-detail-container';
      detailContainer.style.marginTop = '12px';
      parent.insertBefore(detailContainer, parent.firstChild);
    }
    // If same detail is already open, just scroll to it
    var existing = document.getElementById('project-detail-'+pid);
    if(existing){ existing.scrollIntoView({behavior:'smooth'}); return; }
    // remove any previously rendered detail and render this one
    detailContainer.innerHTML = '';
    var wrap = document.createElement('div'); wrap.id = 'project-detail-'+pid; wrap.style.padding='12px'; wrap.style.border='1px solid var(--border)'; wrap.style.borderRadius='8px';
    wrap.innerHTML = `<h3>Проект ${pid}</h3>
      <div style="display:flex;gap:16px;align-items:flex-start">
        <div style="flex:1;min-width:0">
          <div id="activities-${pid}">Загрузка активности...</div>
        </div>
        <div style="width:320px">
          <div id="tasks-${pid}"><strong>Задачи</strong><div>Загрузка...</div></div>
        </div>
      </div>
      <div style="margin-top:8px"><textarea id="activity-input-${pid}" placeholder="Добавить запись в activity..." style="width:100%;min-height:60px"></textarea>
      <div style="margin-top:6px;display:flex;gap:8px"><input id="activity-tid-${pid}" placeholder="Ваш telegram id (для тестов)" style="width:200px"><button id="activity-post-${pid}">Добавить</button></div></div>`;
    detailContainer.appendChild(wrap);
    wrap.scrollIntoView({behavior:'smooth'});
    // load activities
    fetch(`/api/project/${pid}/activities`).then(r=>r.json()).then(arr=>{
      var ael = document.getElementById('activities-'+pid); ael.innerHTML='';
      arr.forEach(a=>{
        var it = document.createElement('div'); it.style.padding='8px 0'; it.innerHTML = `<div style="font-weight:600">${a.actor||'Система'}</div><div style="color:var(--muted);font-size:13px">${new Date(a.created_at).toLocaleString()}</div><div style="margin-top:6px">${a.text}</div><div style="margin-top:6px"><a href="#" data-aid="${a.id}" class="open-comments">Комментарии</a></div>`;
        ael.appendChild(it);
      });
      // attach comment toggles
      document.querySelectorAll(`#activities-${pid} .open-comments`).forEach(el=>el.addEventListener('click', function(e){ e.preventDefault(); var aid=this.dataset.aid; openComments(pid, aid); }));
    });
    // load tasks
    fetch(`/api/project/${pid}/tasks`).then(r=>r.json()).then(arr=>{
      var tel = document.getElementById('tasks-'+pid); tel.innerHTML = '<strong>Задачи</strong>';
      var list = document.createElement('div'); list.style.display='flex'; list.style.flexDirection='column'; list.style.gap='8px';
      arr.forEach(t=>{
        var it = document.createElement('div'); it.style.padding='8px'; it.style.border='1px solid rgba(255,255,255,0.03)'; it.style.borderRadius='6px'; it.innerHTML = `<div style="font-weight:600">${t.title}</div><div style="color:var(--muted)">Статус: ${t.status} ${t.assignee_id?('• @'+t.assignee_id):''}</div>`;
        list.appendChild(it);
      });
      // add create task form
      var form = document.createElement('div'); form.style.marginTop='8px'; form.innerHTML = `<input id="task-title-${pid}" placeholder="Название задачи" style="width:100%;padding:6px;border:1px solid var(--border);border-radius:6px"><input id="task-assignee-${pid}" placeholder="Assignee tg id" style="width:100%;padding:6px;border:1px solid var(--border);border-radius:6px;margin-top:6px"><button id="task-create-${pid}" style="margin-top:6px">Создать задачу</button>`;
      tel.appendChild(list); tel.appendChild(form);
      document.getElementById('task-create-'+pid).addEventListener('click', async ()=>{
        var title = document.getElementById('task-title-'+pid).value;
        var ass = document.getElementById('task-assignee-'+pid).value;
        if(!title) return alert('Введите название');
        var res = await fetch(`/api/project/${pid}/tasks`, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({title: title, assignee_telegram_id: ass})});
        if(res.ok){ loadProjectDetail(pid); }
      });
    });
    // hook up post activity
    var postBtn = document.getElementById('activity-post-'+pid);
    if(postBtn){
      postBtn.removeEventListener && postBtn.removeEventListener('click', ()=>{});
      postBtn.addEventListener('click', async ()=>{
      var txt = document.getElementById('activity-input-'+pid).value;
      var tid = document.getElementById('activity-tid-'+pid).value;
      if(!txt) return alert('Введите текст');
      await fetch(`/api/project/${pid}/activity`, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({text: txt, telegram_id: tid})});
      document.getElementById('activity-input-'+pid).value='';
      document.getElementById('activity-tid-'+pid).value='';
      loadProjectDetail(pid);
      });
    }
    // listen for socketio events (if socket connected earlier)
    try{ if(window.socket){ window.socket.emit('join', {project_id: pid}); }
    }catch(e){}
  }

  function openComments(pid, aid){
    var ael = document.getElementById('activities-'+pid);
    var node = Array.from(ael.children).find(n=> n.querySelector && n.querySelector('[data-aid]') && n.querySelector('[data-aid]').dataset.aid==aid);
    if(!node){ alert('Найти комментарии не удалось'); return; }
    // insert simple comments UI
    var cbox = document.createElement('div'); cbox.style.marginTop='8px'; cbox.innerHTML = `<div id="comments-${aid}">Загрузка...</div><textarea id="comment-input-${aid}" style="width:100%;min-height:60px"></textarea><input id="comment-tid-${aid}" placeholder="Ваш telegram id"><button id="comment-post-${aid}">Комментировать</button>`;
    node.appendChild(cbox);
    // load comments via socket? no direct endpoint, reuse ActivityComment DB via a new minimal endpoint (not implemented) — use fallback: show placeholder
    document.getElementById('comment-post-'+aid).addEventListener('click', async ()=>{
      var txt = document.getElementById('comment-input-'+aid).value; var tid = document.getElementById('comment-tid-'+aid).value; if(!txt||!tid) return alert('Введите текст и ваш tg id');
      await fetch(`/api/activity/${aid}/comment`, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({text: txt, telegram_id: tid})});
      // quick refresh
      loadProjectDetail(pid);
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
    return new Promise(async (resolve, reject)=>{
      var el = document.getElementById('profile-block');
      var currentToken = localStorage.getItem('st');
      // Quick render from Telegram.WebApp.initDataUnsafe for instant UX
      try{
        if(window.Telegram && window.Telegram.WebApp && window.Telegram.WebApp.initDataUnsafe && window.Telegram.WebApp.initDataUnsafe.user){
          var u = window.Telegram.WebApp.initDataUnsafe.user;
          var name = (u.first_name||'') + (u.last_name?(' '+u.last_name):'');
          var usernameHtml = u.username ? `<div class="small">@${u.username}</div>` : '';
          var photo = u.photo_url || '/static/images/avatar.png';
          el.innerHTML = `<div class="profile"><div class="avatar-wrap"><div class="skeleton circle" id="skeleton-avatar" style="width:72px;height:72px"></div><img id="profile-avatar-img" style="display:none;width:72px;height:72px;border-radius:999px;object-fit:cover;border:1px solid rgba(255,255,255,0.06)" src="${photo}" alt="avatar"></div><div class="meta"><div class="name">${name||'Пользователь'}</div>${usernameHtml}<div class="id">telegram: ${u.id}</div><div class="small" style="color: green;">● Онлайн через Telegram</div></div></div>`;
          // replace skeleton when loaded
          loadImageWithSkeleton(document.getElementById('profile-avatar-img'), document.getElementById('skeleton-avatar'));
          try{ if(u.id) localStorage.setItem('tg_id', u.id); }catch(e){}
        }
      }catch(e){ /* ignore */ }
      if(!currentToken){
        // Попытка обмена через Telegram Web App
        var newSt = await telegramExchange();
        if(newSt){
          currentToken = newSt;
        } else {
          // If WebApp is present, try server-side init to get verified user/photo
          if(window.Telegram && window.Telegram.WebApp && window.Telegram.WebApp.initData){
            try{
              var resp = await fetch('/webapp/init', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({initData: window.Telegram.WebApp.initData})});
              if(resp && resp.ok){
                var jw = await resp.json();
                if(jw && jw.ok){
                  var user = jw.user || {};
                  var pname = user.full_name || (user.first_name? (user.first_name + (user.last_name?(' '+user.last_name):'')) : 'Пользователь');
                  var pusername = user.username ? `<div class="small">@${user.username}</div>` : '';
                  var pphoto = jw.photo_url || '/static/images/avatar.png';
                  el.innerHTML = `<div class="profile"><div class="avatar-wrap"><div class="skeleton circle" id="skeleton-avatar" style="width:72px;height:72px"></div><img id="profile-avatar-img" style="display:none;width:72px;height:72px;border-radius:999px;object-fit:cover;border:1px solid rgba(255,255,255,0.06)" src="${pphoto}" alt="avatar"></div><div class="meta"><div class="name">${pname}</div>${pusername}<div class="id">telegram: ${user.id||''}</div><div class="small" style="color: green;">● Онлайн через Telegram</div></div></div>`;
                  loadImageWithSkeleton(document.getElementById('profile-avatar-img'), document.getElementById('skeleton-avatar'));
                  if(user.id) try{ localStorage.setItem('tg_id', user.id); }catch(e){}
                  resolve();
                  return;
                }
              }
            }catch(e){ console.warn('webapp init failed', e); }
          }
          el.innerHTML = '<a href="/auth/telegram?next=/">Войти через Telegram</a>';
          resolve();
          return;
        }
      }
  fetch('/api/me?st='+currentToken).then(r=>r.json()).then(async d=>{
        if(d.error){
          // Токен истек, попробуем обновить через Telegram Web App
          telegramExchange().then(newSt=>{
            if(newSt){
              localStorage.setItem('st', newSt);
              // Рекурсивно загрузить профиль с новым токеном
              loadProfile().then(resolve).catch(reject);
            } else {
              try{
                if(window.Telegram && window.Telegram.WebApp && window.Telegram.WebApp.initDataUnsafe && window.Telegram.WebApp.initDataUnsafe.user){
                  var u = window.Telegram.WebApp.initDataUnsafe.user;
                  var name = (u.first_name||'') + (u.last_name?(' '+u.last_name):'');
                  var status = '<div class="small" style="color: green;">● Онлайн через Telegram</div>';
                  el.innerHTML = `<div class="profile"><div style="width:72px;height:72px;border-radius:999px;background:#efefef"></div><div class="meta"><div class="name">${name||'Пользователь'}</div><div class="id">telegram: ${u.id}</div>${status}</div></div>`;
                  localStorage.setItem('tg_id', u.id);
                } else {
                  var st = localStorage.getItem('st');
                  if(st && /^\d+$/.test(st)){
                    var status = '<div class="small" style="color: green;">● Онлайн через Telegram</div>';
                    el.innerHTML = `<div class="profile"><div style="width:72px;height:72px;border-radius:999px;background:#efefef"></div><div class="meta"><div class="name">Пользователь</div><div class="id">telegram: ${st}</div>${status}</div></div>`;
                    localStorage.setItem('tg_id', st);
                  } else {
                    el.innerHTML = '<a href="/auth/telegram?next=/">Войти через Telegram</a>';
                  }
                }
              }catch(e){ el.innerHTML = '<a href="/auth/telegram?next=/">Войти через Telegram</a>'; }
              resolve();
            }
          }).catch(()=>{
            el.innerHTML = '<div class="small">Не удалось загрузить профиль</div>';
            resolve();
          });
          return;
        }
        var photo = d.photo_url || '';
        var first = d.first_seen ? new Date(d.first_seen).toLocaleString() : '';
        function applyProfile(src){
          var status = '';
          if(window.Telegram && window.Telegram.WebApp){
            status = '<div class="small" style="color: green;">● Онлайн через Telegram</div>';
          }
          var username = d.username ? `<div class=\"small\">@${d.username}</div>` : '';
          var updateBtn = `<button id=\"update-photo-btn\" style=\"margin-top:8px;\">Обновить фото</button>`;
          el.innerHTML = `<div class=\"profile\">` + (src?`<img src=\"${src}\" alt=\"avatar\">`:`<div style=\"width:72px;height:72px;border-radius:999px;background:#efefef\"></div>`) + `<div class=\"meta\"><div class=\"name\">${d.name || 'Пользователь'}</div>${username}<div class=\"id\">telegram: ${d.telegram_id}</div><div class=\"small\">Первый вход: ${first}</div>${status}${updateBtn}</div></div>`;
          if(d.telegram_id) localStorage.setItem('tg_id', d.telegram_id);
          // Кнопка обновления фото
          var btn = document.getElementById('update-photo-btn');
          if(btn){
            btn.onclick = async function(){
              btn.disabled = true;
              btn.textContent = 'Обновление...';
              // Принудительно обновить профиль через Telegram WebApp (/webapp/init preferred)
              try{
                if(window.Telegram && window.Telegram.WebApp && window.Telegram.WebApp.initData){
                  await fetch('/webapp/init', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({initData: window.Telegram.WebApp.initData})});
                } else {
                  await telegramExchange();
                }
              }catch(e){}
              await loadProfile();
            };
          }
          resolve();
        }
        // If WebApp is present, try server-side init to obtain verified photo/name and override
        if(window.Telegram && window.Telegram.WebApp && window.Telegram.WebApp.initData){
          try{
            var resp2 = await fetch('/webapp/init', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({initData: window.Telegram.WebApp.initData})});
            if(resp2 && resp2.ok){
              var jw2 = await resp2.json();
              if(jw2 && jw2.ok){
                if(jw2.user && jw2.user.full_name) d.name = jw2.user.full_name;
                if(jw2.user && jw2.user.username) d.username = jw2.user.username;
                if(jw2.photo_url) { photo = jw2.photo_url; }
              }
            }
          }catch(e){ console.warn('webapp init (post-me) failed', e); }
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
    // Ensure Telegram WebApp is initialised so initData/initDataUnsafe become available
    try{
      if(window.Telegram && window.Telegram.WebApp && typeof window.Telegram.WebApp.ready === 'function'){
        window.Telegram.WebApp.ready();
      }
      // If initData is present immediately after ready(), try server-side init to fetch verified data
      if(window.Telegram && window.Telegram.WebApp && window.Telegram.WebApp.initData){
        try{
          var respInitNow = await fetch('/webapp/init', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({initData: window.Telegram.WebApp.initData})});
          if(respInitNow && respInitNow.ok){
            var jnow = await respInitNow.json();
            if(jnow && jnow.ok){
              // update quick profile block if exists
              var el = document.getElementById('profile-block');
              if(el){
                var user = jnow.user || {};
                var pname = user.full_name || (user.first_name? (user.first_name + (user.last_name?(' '+user.last_name):'')) : 'Пользователь');
                var pusername = user.username ? `<div class="small">@${user.username}</div>` : '';
                var pphoto = jnow.photo_url || '/static/images/avatar.png';
                el.innerHTML = `<div class="profile"><img src="${pphoto}" alt="avatar"><div class="meta"><div class="name">${pname}</div>${pusername}<div class="id">telegram: ${user.id||''}</div><div class="small" style="color: green;">● Онлайн через Telegram</div></div></div>`;
                try{ if(user.id) localStorage.setItem('tg_id', user.id); }catch(e){}
              }
            }
          }
        }catch(e){ /* ignore */ }
      }
    }catch(e){ /* ignore */ }
    var tokenNow = localStorage.getItem('st');
    if(!tokenNow && window.Telegram && window.Telegram.WebApp && (window.Telegram.WebApp.initData || window.Telegram.WebApp.initDataUnsafe)){
      await telegramExchange();
    }
    // If bottom navigation exists, expose its height via CSS var and add body class
    try{
      var gNav = document.getElementById('global-bottom-nav');
      if(gNav){
        var rect = gNav.getBoundingClientRect();
        var h = Math.ceil(rect.height) + 8; // small buffer
        document.documentElement.style.setProperty('--bottom-nav-height', h + 'px');
        document.body.classList.add('with-bottom-nav');
      }
    }catch(e){/* ignore */}
    var hash = location.hash.replace('#','') || 'projects';
    showTab(hash);
    document.querySelectorAll('.tab-link').forEach(btn=>btn.addEventListener('click', function(e){ showTab(this.dataset.tab); }));
    loadProjects();
  await runSplashLoad();

    // Обработчик кнопки обновления профиля
    var refreshBtn = document.getElementById('refresh-profile');
    if(refreshBtn){
      refreshBtn.addEventListener('click', async ()=>{
        refreshBtn.disabled = true;
        refreshBtn.textContent = 'Обновление...';
        await loadProfile();
        refreshBtn.disabled = false;
        refreshBtn.textContent = 'Обновить профиль';
      });
    }
  });
  async function runSplashLoad(){
    var bar = document.getElementById('splash-bar');
    var pct = document.getElementById('splash-percent');
  try{ document.body.classList.add('splash-open'); }catch(e){}
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
    if(sp){
      // ensure transition has time to run then fully hide
      sp.classList.add('splash-hidden');
      try{ document.body.classList.remove('splash-open'); }catch(e){}
      // remove pointer events and then remove element after transition
      setTimeout(function(){ try{ sp.style.display='none'; sp.style.pointerEvents='none'; }catch(e){} }, 600);
    }
  }

  // Helper: load image and remove skeleton on load or after timeout
  function loadImageWithSkeleton(imgEl, skeletonEl){
    if(!imgEl) return;
    var t = setTimeout(function(){ // fallback in 3s
      try{ if(skeletonEl) skeletonEl.style.display='none'; if(imgEl) imgEl.style.display='block'; }catch(e){}
    }, 3000);
    imgEl.onload = function(){ clearTimeout(t); try{ if(skeletonEl) skeletonEl.style.display='none'; imgEl.style.display='block'; }catch(e){} };
    imgEl.onerror = function(){ clearTimeout(t); try{ if(skeletonEl) skeletonEl.style.background='#333'; skeletonEl.style.display='block'; imgEl.style.display='none'; }catch(e){} };
  }
})();
