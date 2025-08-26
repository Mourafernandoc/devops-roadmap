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
    const tocContainer = document.getElementById('toc');
    if (!container) return;
    try {
      const response = await fetch('devops-complete-roadmap.md');
      if (!response.ok) throw new Error(`Falha ao carregar Markdown: ${response.status}`);
      const mdText = await response.text();
      // Usando Marked (injetado via CDN no index.html)
      container.innerHTML = marked.parse(mdText, { breaks: true });

      // Gerar IDs únicos para títulos e TOC
      const headings = container.querySelectorAll('h1, h2, h3');
      const slugify = str => str.toLowerCase().replace(/[^a-z0-9\s-]/g, '').trim().replace(/\s+/g, '-');
      const used = new Map();
      headings.forEach(h => {
        const base = slugify(h.textContent);
        const count = used.get(base) || 0;
        const id = count ? `${base}-${count}` : base;
        used.set(base, count + 1);
        h.id = id;
      });

      // Montar TOC
      if (tocContainer) {
        const list = document.createElement('ul');
        headings.forEach(h => {
          const level = h.tagName === 'H1' ? 1 : h.tagName === 'H2' ? 2 : 3;
          const li = document.createElement('li');
          li.className = `toc-l${level}`;
          const a = document.createElement('a');
          a.href = `#${h.id}`;
          a.textContent = h.textContent;
          li.appendChild(a);
          list.appendChild(li);
        });
        tocContainer.innerHTML = '';
        tocContainer.appendChild(list);
      }
    } catch (err) {
      container.innerHTML = `<p style="color:#f66">Erro ao carregar conteúdo: ${err.message}</p>`;
    }
  })();

  // Voltar ao topo
  const backToTop = document.getElementById('backToTop');
  if (backToTop) {
    backToTop.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
    const onScroll = () => {
      if (window.scrollY > 400) backToTop.classList.add('show'); else backToTop.classList.remove('show');
    };
    window.addEventListener('scroll', onScroll);
    onScroll();
  }
  