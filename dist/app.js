// artefactools-platform · cliente de demo (vanilla JS)
(function(){
  var base = window.location.origin;
  var msgs = document.getElementById('msgs');
  var input = document.getElementById('msg');
  var send = document.getElementById('send');
  var status = document.getElementById('status');

  function addBubble(text, kind){
    var el = document.createElement('div');
    el.className = 'bubble ' + kind;
    el.textContent = text;
    el.classList.add('fade-in');
    msgs.appendChild(el);
    msgs.scrollTop = msgs.scrollHeight;
    return el;
  }

  function setStatus(text, ok){
    status.textContent = text;
    status.style.color = ok ? 'var(--accent-2)' : 'var(--danger)';
  }

  function load(){
    return fetch(base + '/api/messages').then(function(r){ return r.json(); }).then(function(data){
      if(data.messages && data.messages.length){
        msgs.innerHTML = '';
        data.messages.slice().reverse().forEach(function(m){
          addBubble(m.content, m.role === 'user' ? 'me' : 'them');
        });
        setStatus('Historial cargado (' + data.messages.length + ' mensajes).', true);
      }
    }).catch(function(e){
      setStatus('No se pudo cargar el historial: ' + e.message, false);
    });
  }

  function sendMsg(){
    var text = input.value.trim();
    if(!text) return;
    send.disabled = true;
    addBubble(text, 'me');
    input.value = '';
    setStatus('Enviando…', true);
    return fetch(base + '/api/messages', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({role:'user', content:text})
    }).then(function(r){ return r.json(); }).then(function(data){
      if(data.ok){
        setTimeout(function(){
          addBubble('Recibido y guardado en la sesión (UserSessionDO + SQLite).', 'them');
          setStatus('Mensaje guardado correctamente.', true);
        }, 400);
      } else {
        setStatus('Error: ' + (data.error || 'desconocido'), false);
      }
    }).catch(function(e){
      setStatus('Error de red: ' + e.message, false);
    }).finally(function(){
      send.disabled = false;
      input.focus();
    });
  }

  send.addEventListener('click', sendMsg);
  input.addEventListener('keydown', function(e){ if(e.key === 'Enter') sendMsg(); });

  fetch(base + '/health').then(function(r){ return r.json(); }).then(function(d){
    setStatus('API viva en ' + d.service + ' · ' + new Date(d.ts).toLocaleTimeString(), true);
  }).catch(function(){
    setStatus('API no disponible (Worker no desplegado o sin respuesta).', false);
  });

  load();
})();
