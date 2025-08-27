// Минимальный клиент для чата: сначала пытаемся подключиться к SocketIO, если не получается — polling каждые 60s
(function(){
  function qs(q){return document.querySelector(q)}
  const chatEl = qs('#chat');
  if(!chatEl) return;
  const pid = chatEl.getAttribute('data-project-id');
  const messagesEl = qs('#messages');
  const form = qs('#msgform');
  const input = qs('#msgtext');

  let lastId = 0;
  function appendMsg(m){
    const d = document.createElement('div');
    d.textContent = `${m.user}: ${m.text}`;
    messagesEl.appendChild(d);
    lastId = Math.max(lastId, m.id || 0);
  }

  // Try SocketIO
  let socket, socketOK=false;
  try{
    socket = io();
    socket.on('connect', ()=>{
      socketOK = true;
      socket.emit('join', {project_id: pid});
    });
    socket.on('message', function(m){ appendMsg(m); });
  }catch(e){ socketOK=false; }

  // Polling fallback
  async function poll(){
    try{
      const res = await fetch(`/api/project/${pid}/messages?after=${lastId}`);
      if(res.ok){
        const arr = await res.json();
        arr.forEach(appendMsg);
      }
    }catch(e){ console.error(e); }
  }

  // Try polling every 60s if SocketIO not available
  setInterval(()=>{ if(!socketOK) poll(); }, 60000);
  // initial poll
  poll();

  if(form){
    form.addEventListener('submit', async function(ev){
      ev.preventDefault();
      const text = input.value.trim();
      if(!text) return;
      // send via API (anonymous from admin panel)
      await fetch(`/api/project/${pid}/message`, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({telegram_id: 'admin', text})});
      input.value='';
      // optimistic append
      appendMsg({id: lastId+1, user: 'admin', text, created_at: new Date().toISOString()});
    });
  }
})();
