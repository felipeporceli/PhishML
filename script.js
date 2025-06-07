// Função de rolagem suave com desaceleração ao clicar nos links
document.querySelectorAll('nav a').forEach(anchor => {
  anchor.addEventListener('click', function(e) {
      e.preventDefault(); // Previne o comportamento padrão do link
      
      // Obtém o destino do link
      const targetId = this.getAttribute('href').substring(1);  // Remove o "#" do href
      const targetElement = document.getElementById(targetId);

      // Rolagem suave até o destino
      targetElement.scrollIntoView({
          behavior: 'smooth', // Define o comportamento suave
          block: 'start', // Garante que a rolagem pare no topo do elemento
      });
  });
});

// Verificações

function isPhishing(url) {
  return url.includes("phish") || url.includes("malicious");
}

document.getElementById('check-url').addEventListener('click', verificarUrl);

function verificarUrl() {
  const url = document.getElementById('url-input').value.trim();
  const section = document.getElementById('detectar-phishing');
  const feedback = document.getElementById('feedback-message');
  const phishD = document.getElementById('phish-details');
  const legitD = document.getElementById('legit-details');
  const loading = document.getElementById('loading-overlay');

  // Reset da interface
  section.className = '';
  feedback.textContent = '';
  phishD.style.display = 'none';
  legitD.style.display = 'none';

  // Mostrar GIF de carregamento
  loading.style.display = 'flex';

  fetch('http://127.0.0.1:5000/predict', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ url })
  })
    .then(res => res.json())
    .then(data => {
      if (data.error) {
        section.classList.add('shake', 'expanded-error');
        feedback.textContent = 'Erro do servidor: ' + data.error;
        feedback.style.color = '#000';
        return;
      }

      if (data.resultado === 1) {
        section.classList.add('green-bg', 'expanded-legit');
        feedback.textContent = '✅ Esta URL parece segura.';
        feedback.style.color = '#fff';
        fadeTextSequential(legitD);
      } else {
        section.classList.add('red-bg', 'expanded-phish');
        feedback.textContent = '⚠️ Alerta: Este site parece ser um phishing!';
        feedback.style.color = '#fff';
        fadeTextSequential(phishD);
      }
    })
    .catch(error => {
      section.classList.add('shake', 'expanded-error');
      feedback.textContent = 'Erro ao conectar com o servidor Flask.';
      feedback.style.color = '#000';
      console.error('Erro na requisição:', error);
    })
    .finally(() => {
      // Ocultar GIF de carregamento
      loading.style.display = 'none';
    });
}

function isValidUrl(url) {
  const regex = /^(https?:\/\/)?(www\.)?([\w-]+\.)+[a-z]{2,7}(\/[^\s]*)?$/i;
  return regex.test(url);
}

// Faz fade sequencial de até 3s
function fadeTextSequential(container) {
  const text = container.textContent.trim();
  const words = text.split(/\s+/);
  const duration = 4000;
  const interval = duration / words.length;

  container.innerHTML = '';
  container.style.display = 'block';
  words.forEach((w, i) => {
    const span = document.createElement('span');
    span.textContent = w + ' ';
    span.style.opacity = 0;
    span.style.transition = 'opacity 0.3s ease';
    container.appendChild(span);
    setTimeout(() => (span.style.opacity = 1), interval * i);
  });
}


