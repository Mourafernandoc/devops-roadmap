// Geração de TOC e personalização para conteúdo dentro do iframe
(function initIframeTOC() {
  const iframe = document.getElementById('markdownFrame');
  const tocContainer = document.getElementById('toc');
  if (!iframe || !tocContainer) return;

  const slugify = str => str
    .toLowerCase()
    .normalize('NFD').replace(/\p{Diacritic}/gu, '')
    .replace(/[^a-z0-9\s-]/g, '')
    .trim().replace(/\s+/g, '-');

  const buildTOC = (doc) => {
    const used = new Map();
    const headings = doc.querySelectorAll('h1, h2, h3');

    // Envolver conteúdo com classe markdown e injetar CSS
    const body = doc.body;
    if (body && !body.querySelector('.markdown')) {
      const wrapper = doc.createElement('div');
      wrapper.className = 'markdown';
      while (body.firstChild) wrapper.appendChild(body.firstChild);
      body.appendChild(wrapper);
      const link = doc.createElement('link');
      link.rel = 'stylesheet';
      link.href = 'sytles.css';
      doc.head.appendChild(link);
    }

    headings.forEach(h => {
      const base = slugify(h.textContent || 'secao');
      const count = used.get(base) || 0;
      const id = count ? `${base}-${count}` : base;
      used.set(base, count + 1);
      h.id = h.id || id;
    });

    const list = document.createElement('ul');
    headings.forEach(h => {
      const level = h.tagName === 'H1' ? 1 : h.tagName === 'H2' ? 2 : 3;
      const li = document.createElement('li');
      li.className = `toc-l${level}`;
      const a = document.createElement('a');
      a.href = `#${h.id}`;
      a.textContent = h.textContent;
      a.addEventListener('click', (e) => {
        e.preventDefault();
        const target = doc.getElementById(h.id);
        if (target) target.scrollIntoView({ behavior: 'smooth' });
      });
      li.appendChild(a);
      list.appendChild(li);
    });
    tocContainer.innerHTML = '';
    tocContainer.appendChild(list);
  };

  const autoResize = (doc) => {
    const update = () => {
      const height = doc.documentElement.scrollHeight || doc.body.scrollHeight;
      iframe.style.height = Math.max(600, height + 20) + 'px';
    };
    update();
    // Recalcular em mudanças de tamanho dentro do iframe
    iframe.contentWindow.addEventListener('resize', update);
    // E após pequenas esperas (conteúdos assíncronos eventuais)
    setTimeout(update, 250);
    setTimeout(update, 1000);
  };

  iframe.addEventListener('load', () => {
    const doc = iframe.contentDocument;
    if (!doc) return;
    buildTOC(doc);
    autoResize(doc);
  });
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
  