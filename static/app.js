/* ── Falco Rule Studio — Frontend Application ── */

// ── Tab Navigation ──
document.querySelectorAll('.nav-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    const id = tab.dataset.tab;
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(`tab-${id}`).classList.add('active');
  });
});

// ── Toast Notifications ──
function showToast(msg, type = 'success') {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.className = `toast show ${type}`;
  setTimeout(() => { toast.className = 'toast'; }, 3000);
}

// ── YAML Syntax Highlighter ──
function highlightYaml(code) {
  return code
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    // Comments
    .replace(/(#[^\n]*)/g, '<span class="cm">$1</span>')
    // YAML keys
    .replace(/^(\s*)([\w\-]+)(\s*):/gm, '$1<span class="key">$2</span>$3:')
    // Strings in quotes
    .replace(/"([^"]*)"/g, '"<span class="str">$1</span>"')
    .replace(/'([^']*)'/g, '\'<span class="str">$1</span>\'')
    // Priority values
    .replace(/\b(EMERGENCY|ALERT|CRITICAL|ERROR|WARNING|NOTICE|INFORMATIONAL|DEBUG)\b/g,
      '<span class="num">$1</span>')
    // Boolean / null
    .replace(/\b(true|false|null)\b/g, '<span class="kw">$1</span>');
}

// ── Simple Markdown Renderer ──
function renderMarkdown(text) {
  return text
    // Headings
    .replace(/^### (.+)$/gm, '<h3>$1</h3>')
    .replace(/^## (.+)$/gm, '<h2>$1</h2>')
    .replace(/^# (.+)$/gm, '<h2>$1</h2>')
    // Bold
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    // Italic
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    // Code blocks
    .replace(/```(?:yaml|bash|sh|json|text)?\n([\s\S]*?)```/g,
      '<pre><code>$1</code></pre>')
    // Inline code
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    // Unordered lists
    .replace(/^[-*] (.+)$/gm, '<li>$1</li>')
    .replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>')
    // Numbered lists
    .replace(/^\d+\. (.+)$/gm, '<li>$1</li>')
    // Paragraphs (wrap isolated lines)
    .replace(/^(?!<[h|u|l|p|p]|$)(.+)$/gm, '<p>$1</p>')
    // Clean up: collapse multiple ul/ol tags
    .replace(/<\/li>\n<li>/g, '</li><li>')
    .replace(/<li>/g, '<li>')
    .replace(/<\/ul>\n<ul>/g, '');
}

// ── Copy to Clipboard ──
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    showToast('Copied to clipboard!', 'success');
  } catch {
    showToast('Copy failed', 'error');
  }
}

// ── API Calls ──
async function apiPost(endpoint, body) {
  const res = await fetch(`/api/${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

// ── Load Examples ──
let exampleRules = [];
let lastGeneratedRule = '';

async function loadExamples() {
  try {
    const data = await fetch('/api/examples').then(r => r.json());

    // Example prompt chips
    const chipList = document.getElementById('example-prompts');
    data.prompts.forEach(prompt => {
      const chip = document.createElement('button');
      chip.className = 'chip';
      chip.textContent = prompt;
      chip.onclick = () => {
        document.getElementById('gen-description').value = prompt;
        document.getElementById('gen-description').focus();
      };
      chipList.appendChild(chip);
    });

    // Example rule cards
    exampleRules = data.rules;
    const cardsContainer = document.getElementById('example-cards');
    data.rules.forEach((rule, i) => {
      const card = document.createElement('div');
      card.className = 'example-card';
      card.innerHTML = `
        <h3>${rule.title}</h3>
        <p>${rule.description}</p>
        <span class="card-tag">Click to load in editor</span>
      `;
      card.onclick = () => loadExampleRule(rule);
      cardsContainer.appendChild(card);
    });
  } catch (e) {
    console.error('Failed to load examples:', e);
  }
}

function loadExampleRule(rule) {
  const out = document.getElementById('gen-output');
  lastGeneratedRule = rule.yaml;
  out.innerHTML = `<pre>${highlightYaml(rule.yaml)}</pre>`;
  document.getElementById('gen-actions').style.display = 'flex';
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ── Generate Rule ──
document.getElementById('btn-generate').addEventListener('click', async () => {
  const desc = document.getElementById('gen-description').value.trim();
  if (!desc) { showToast('Please enter a security requirement', 'error'); return; }

  const btn = document.getElementById('btn-generate');
  const out = document.getElementById('gen-output');
  const loader = document.getElementById('gen-loader');
  const actions = document.getElementById('gen-actions');

  btn.disabled = true;
  out.innerHTML = '';
  loader.style.display = 'flex';
  actions.style.display = 'none';

  try {
    const data = await apiPost('generate', {
      description: desc,
      context: document.getElementById('gen-context').value,
      severity: document.getElementById('gen-severity').value,
      tags: [],
    });

    if (data.success && data.rule_yaml) {
      lastGeneratedRule = data.rule_yaml;
      out.innerHTML = `<pre>${highlightYaml(data.rule_yaml)}</pre>`;
      actions.style.display = 'flex';
      showToast('Rule generated successfully!', 'success');
    } else {
      out.innerHTML = `<div class="empty-state"><p style="color:var(--error)">Generation failed: ${(data.errors || []).join(', ')}</p></div>`;
    }
  } catch (e) {
    out.innerHTML = `<div class="empty-state"><p style="color:var(--error)">Error: ${e.message}</p></div>`;
    showToast('Generation failed', 'error');
  } finally {
    btn.disabled = false;
    loader.style.display = 'none';
  }
});

// ── Copy Generated Rule ──
document.getElementById('btn-copy-gen').addEventListener('click', () => {
  if (lastGeneratedRule) copyText(lastGeneratedRule);
});

// ── Send Generated Rule to Explain Tab ──
document.getElementById('btn-explain-generated').addEventListener('click', () => {
  if (!lastGeneratedRule) return;
  document.getElementById('explain-input').value = lastGeneratedRule;
  document.querySelector('[data-tab="explain"]').click();
});

// ── Send Generated Rule to Validate Tab ──
document.getElementById('btn-validate-generated').addEventListener('click', () => {
  if (!lastGeneratedRule) return;
  document.getElementById('validate-input').value = lastGeneratedRule;
  document.querySelector('[data-tab="validate"]').click();
});

// ── Explain Rule ──
document.getElementById('btn-explain').addEventListener('click', async () => {
  const yaml = document.getElementById('explain-input').value.trim();
  if (!yaml) { showToast('Please paste a Falco rule', 'error'); return; }

  const btn = document.getElementById('btn-explain');
  const out = document.getElementById('explain-output');
  const loader = document.getElementById('explain-loader');

  btn.disabled = true;
  out.innerHTML = '';
  loader.style.display = 'flex';

  try {
    const data = await apiPost('explain', { rule_yaml: yaml });
    if (data.success && data.explanation) {
      out.innerHTML = renderMarkdown(data.explanation);
    } else {
      out.innerHTML = `<div class="empty-state"><p style="color:var(--error)">Failed to explain rule</p></div>`;
    }
  } catch (e) {
    out.innerHTML = `<div class="empty-state"><p style="color:var(--error)">Error: ${e.message}</p></div>`;
  } finally {
    btn.disabled = false;
    loader.style.display = 'none';
  }
});

// ── Validate Rule ──
document.getElementById('btn-validate').addEventListener('click', async () => {
  const yaml = document.getElementById('validate-input').value.trim();
  if (!yaml) { showToast('Please paste a Falco rule', 'error'); return; }

  const btn = document.getElementById('btn-validate');
  const out = document.getElementById('validate-output');
  const loader = document.getElementById('validate-loader');

  btn.disabled = true;
  out.innerHTML = '';
  loader.style.display = 'flex';

  try {
    const data = await apiPost('validate', { rule_yaml: yaml });

    const errors = data.errors || [];
    const warnings = data.warnings || [];
    const suggestions = data.suggestions || [];
    const isValid = data.success && errors.length === 0;

    let html = `
      <div class="validation-card ${isValid ? 'pass' : 'fail'}">
        <div class="validation-status">
          <span class="status-icon">${isValid ? '✅' : '❌'}</span>
          <span>${isValid ? 'Rule is Valid' : 'Validation Failed'}</span>
        </div>
    `;

    if (errors.length > 0) {
      html += `<div class="validation-section">
        <h4 class="err">Errors (${errors.length})</h4>
        ${errors.map(e => `<div class="validation-item err">⛔ ${e}</div>`).join('')}
      </div>`;
    }

    if (warnings.length > 0) {
      html += `<div class="validation-section">
        <h4 class="warn">Warnings (${warnings.length})</h4>
        ${warnings.map(w => `<div class="validation-item warn">⚠️ ${w}</div>`).join('')}
      </div>`;
    }

    if (suggestions.length > 0) {
      html += `<div class="validation-section">
        <h4 class="sug">Suggestions (${suggestions.length})</h4>
        ${suggestions.map(s => `<div class="validation-item sug">💡 ${s}</div>`).join('')}
      </div>`;
    }

    if (isValid && warnings.length === 0 && suggestions.length === 0) {
      html += `<p style="color:var(--success);margin-top:10px;font-size:13px">
        Perfect! This rule follows all best practices.
      </p>`;
    }

    html += '</div>';
    out.innerHTML = html;
    showToast(isValid ? 'Rule is valid!' : 'Validation issues found', isValid ? 'success' : 'error');
  } catch (e) {
    out.innerHTML = `<div class="empty-state"><p style="color:var(--error)">Error: ${e.message}</p></div>`;
  } finally {
    btn.disabled = false;
    loader.style.display = 'none';
  }
});

// ── Optimize Rule ──
document.getElementById('btn-optimize').addEventListener('click', async () => {
  const yaml = document.getElementById('optimize-input').value.trim();
  if (!yaml) { showToast('Please paste a Falco rule', 'error'); return; }

  const btn = document.getElementById('btn-optimize');
  const out = document.getElementById('optimize-output');
  const loader = document.getElementById('optimize-loader');

  btn.disabled = true;
  out.innerHTML = '';
  loader.style.display = 'flex';

  try {
    const data = await apiPost('optimize', { rule_yaml: yaml });
    if (data.success && data.explanation) {
      out.innerHTML = renderMarkdown(data.explanation);
    } else {
      out.innerHTML = `<div class="empty-state"><p style="color:var(--error)">Optimization failed</p></div>`;
    }
  } catch (e) {
    out.innerHTML = `<div class="empty-state"><p style="color:var(--error)">Error: ${e.message}</p></div>`;
  } finally {
    btn.disabled = false;
    loader.style.display = 'none';
  }
});

// ── Chat ──
const chatHistory = [];

function addChatMessage(role, content, isTyping = false) {
  const msgs = document.getElementById('chat-messages');
  const el = document.createElement('div');
  el.className = `chat-message ${role}`;
  el.dataset.role = role;

  if (isTyping) {
    el.id = 'typing-indicator';
    el.innerHTML = `<div class="chat-bubble">
      <div class="typing-indicator">
        <div class="typing-dot"></div>
        <div class="typing-dot"></div>
        <div class="typing-dot"></div>
      </div>
    </div>`;
  } else {
    const formatted = formatChatMessage(content);
    el.innerHTML = `<div class="chat-bubble">${formatted}</div>`;
  }

  msgs.appendChild(el);
  msgs.scrollTop = msgs.scrollHeight;
  return el;
}

function formatChatMessage(text) {
  // Minimal markdown for chat
  return text
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/```(?:yaml|bash|sh|json|text)?\n([\s\S]*?)```/g,
      '<pre><code>$1</code></pre>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/^[-*] (.+)$/gm, '<li>$1</li>')
    .replace(/\n/g, '<br>');
}

async function sendChatMessage() {
  const input = document.getElementById('chat-input');
  const msg = input.value.trim();
  if (!msg) return;

  const btn = document.getElementById('btn-chat-send');
  input.value = '';
  btn.disabled = true;

  addChatMessage('user', msg);
  chatHistory.push({ role: 'user', content: msg });

  const typingEl = addChatMessage('assistant', '', true);

  try {
    const data = await apiPost('chat', {
      message: msg,
      history: chatHistory.slice(-10), // Keep last 10 messages
    });

    typingEl.remove();
    const assistantMsg = data.response;
    addChatMessage('assistant', assistantMsg);
    chatHistory.push({ role: 'assistant', content: assistantMsg });
  } catch (e) {
    typingEl.remove();
    addChatMessage('assistant', `Sorry, I encountered an error: ${e.message}`);
  } finally {
    btn.disabled = false;
    input.focus();
  }
}

document.getElementById('btn-chat-send').addEventListener('click', sendChatMessage);

document.getElementById('chat-input').addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendChatMessage();
  }
});

function insertChatMsg(text) {
  document.getElementById('chat-input').value = text;
  document.getElementById('chat-input').focus();
}

// ── Initialize ──
loadExamples();
