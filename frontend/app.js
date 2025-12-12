(function(){
  const $ = sel => document.querySelector(sel);
  const authBox = $('#auth');
  const loginForm = $('#loginForm');
  const registerForm = $('#registerForm');
  const chatBox = $('#chat');
  const meSpan = $('#me');
  const messagesEl = $('#messages');
  const toInput = $('#to');
  const contentInput = $('#content');
  const btnLogin = $('#btnLogin');
  const btnRegister = $('#btnRegister');
  const btnSend = $('#btnSend');
  const btnLogout = $('#btnLogout');
  const loginMsg = $('#loginMsg');
  const registerMsg = $('#registerMsg');
  const toggleRegister = $('#toggleRegister');
  const toggleLogin = $('#toggleLogin');

  let ws = null;
  let token = localStorage.getItem('sdchat.token') || null;
  let username = localStorage.getItem('sdchat.user') || null;
  const seenIds = new Set();

  function showAuth(){ authBox.classList.remove('hidden'); chatBox.classList.add('hidden'); }
  function showLoginForm(){ loginForm.classList.remove('hidden'); registerForm.classList.add('hidden'); }
  function showRegisterForm(){ loginForm.classList.add('hidden'); registerForm.classList.remove('hidden'); }
  function showChat(){ authBox.classList.add('hidden'); chatBox.classList.remove('hidden'); }

  function appendMessage(text, who){
    const div = document.createElement('div');
    div.className = 'msg ' + (who === 'me' ? 'me' : 'other');
    div.textContent = text;
    messagesEl.appendChild(div);
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  async function doLogin(){
    const user = $('#username').value.trim();
    const pass = $('#password').value;
    if(!user || !pass){ loginMsg.textContent = 'Informe usuário e senha'; return; }
    loginMsg.textContent = 'Conectando...';
    try{
      const res = await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,password:pass})});
      const j = await res.json();
      if(!j.success){ loginMsg.textContent = j.message || 'Login falhou'; return; }
      token = j.token;
      username = user;
      localStorage.setItem('sdchat.token', token);
      localStorage.setItem('sdchat.user', username);
      loginMsg.textContent = '';
      startWs();
      showChat();
      meSpan.textContent = username;
    }catch(e){ loginMsg.textContent = 'Erro: '+e.message }
  }

  async function doRegister(){
    const user = $('#regUsername').value.trim();
    const pass = $('#regPassword').value;
    const confirm = $('#regConfirm').value;
    if(!user || !pass || !confirm){ registerMsg.textContent = 'Preencha todos os campos'; return; }
    if(pass !== confirm){ registerMsg.textContent = 'Senhas não correspondem'; return; }
    registerMsg.textContent = 'Registrando...';
    try{
      const res = await fetch('/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:user,password:pass})});
      const j = await res.json();
      if(!j.success){ registerMsg.textContent = j.message || 'Registro falhou'; return; }
      registerMsg.textContent = 'Registrado com sucesso! Agora faça login.';
      setTimeout(()=>{ showLoginForm(); registerMsg.textContent = ''; }, 1500);
    }catch(e){ registerMsg.textContent = 'Erro: '+e.message }
  }

  function startWs(){
    if(!token) return;
    const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
    const wsUrl = `${scheme}://${location.host}/ws?token=${encodeURIComponent(token)}`;
    ws = new WebSocket(wsUrl);
    ws.onopen = ()=>{
      (async ()=>{
        // fetch history and render (avoid duplicates using seenIds)
        try{
          const resp = await fetch(`/history?token=${encodeURIComponent(token)}`);
          const j = await resp.json();
          if(j && j.success && Array.isArray(j.history)){
            j.history.forEach(m => {
              if(m && m.id && seenIds.has(m.id)) return;
              if(m && m.id) seenIds.add(m.id);
              const txt = `${m.sender}: ${m.content}`;
              appendMessage(txt, m.sender === username ? 'me' : 'other');
            });
          }
        }catch(err){ console.error('history fetch failed', err) }
        appendMessage('Conectado ao servidor', 'other');
      })();
    };
    ws.onmessage = ev => {
      try{
        const data = JSON.parse(ev.data);
        if(data.type === 'message'){
          // deduplicate by id when available
          if(data.id && seenIds.has(data.id)) return;
          if(data.id) seenIds.add(data.id);
          const txt = `${data.sender}: ${data.content}`;
          appendMessage(txt, data.sender === username ? 'me' : 'other');
        } else if(data.type === 'ack'){
          appendMessage(`Mensagem enviada (id ${data.id})`, 'me');
        } else if(data.type === 'error'){
          appendMessage(`Erro: ${data.message}`, 'other');
        }
      }catch(err){ console.error('invalid msg', ev.data) }
    };
    ws.onclose = ()=>{ appendMessage('Desconectado', 'other'); }
  }

  function doSend(){
    if(!ws || ws.readyState !== WebSocket.OPEN){ appendMessage('WebSocket não conectado', 'other'); return; }
    const to = (toInput.value || '').trim();
    const content = (contentInput.value || '').trim();
    if(!to || !content){ appendMessage('Preencha destinatário e mensagem', 'other'); return; }
    ws.send(JSON.stringify({type:'message', to: to, content: content}));
    contentInput.value = '';
  }

  function doLogout(){
    localStorage.removeItem('sdchat.token');
    localStorage.removeItem('sdchat.user');
    token = null; username = null;
    if(ws) ws.close();
    showLogin();
  }

  btnLogin.addEventListener('click', doLogin);
  btnRegister.addEventListener('click', doRegister);
  btnSend.addEventListener('click', doSend);
  btnLogout.addEventListener('click', doLogout);
  toggleRegister.addEventListener('click', e=>{ e.preventDefault(); showRegisterForm(); });
  toggleLogin.addEventListener('click', e=>{ e.preventDefault(); showLoginForm(); });

  // try auto-login
  if(token && username){
    meSpan.textContent = username;
    startWs();
    showChat();
  } else {
    showAuth();
    showLoginForm();
  }
})();
