// Scroll suave para links internos
document.querySelectorAll('a[href^="#"]').forEach(link => {
    link.addEventListener('click', function (e) {
      e.preventDefault();
      const target = document.querySelector(this.getAttribute('href'));
      if (target) {
        target.scrollIntoView({
          behavior: 'smooth'
        });
      }
    });
  });
  
  // Carregar e renderizar o Markdown principal
  (async function loadMarkdown() {
    const container = document.getElementById('markdown');
    if (!container) return;
    try {
      const response = await fetch('devops-complete-roadmap.md');
      if (!response.ok) throw new Error(`Falha ao carregar Markdown: ${response.status}`);
      const mdText = await response.text();
      // Usando Marked (injetado via CDN no index.html)
      container.innerHTML = marked.parse(mdText, { breaks: true });
    } catch (err) {
      container.innerHTML = `<p style="color:#f66">Erro ao carregar conteúdo: ${err.message}</p>`;
    }
  })();
  