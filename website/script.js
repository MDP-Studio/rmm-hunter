(() => {
  const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const progress = document.querySelector(".scroll-progress");
  const cursorLight = document.querySelector(".cursor-light");
  const revealItems = Array.from(document.querySelectorAll("[data-reveal]"));

  revealItems.forEach((item, index) => {
    item.style.setProperty("--reveal-index", String(index % 6));
  });

  const updateProgress = () => {
    const scrollable = document.documentElement.scrollHeight - window.innerHeight;
    const pct = scrollable > 0 ? (window.scrollY / scrollable) * 100 : 0;
    progress.style.width = `${pct}%`;
  };

  updateProgress();
  window.addEventListener("scroll", updateProgress, { passive: true });

  if (!prefersReduced && "IntersectionObserver" in window) {
    const observer = new IntersectionObserver(
      entries => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.16, rootMargin: "0px 0px -8% 0px" }
    );
    revealItems.forEach(item => observer.observe(item));
    window.setTimeout(() => {
      revealItems.forEach(item => {
        if (item.classList.contains("is-visible")) return;
        const rect = item.getBoundingClientRect();
        if (rect.top < window.innerHeight * 1.25) {
          item.classList.add("is-visible");
        }
      });
    }, 1200);
  } else {
    revealItems.forEach(item => item.classList.add("is-visible"));
  }

  if (!prefersReduced && cursorLight) {
    window.addEventListener(
      "pointermove",
      event => {
        cursorLight.style.opacity = "1";
        cursorLight.style.transform = `translate3d(${event.clientX - 220}px, ${event.clientY - 220}px, 0)`;
      },
      { passive: true }
    );
  }

  const counters = Array.from(document.querySelectorAll("[data-count]"));
  const runCounter = element => {
    const target = Number.parseInt(element.dataset.count, 10);
    const start = performance.now();
    const duration = 1100;
    const tick = now => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      element.textContent = String(Math.round(target * eased));
      if (t < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  };

  if (!prefersReduced && "IntersectionObserver" in window) {
    const counterObserver = new IntersectionObserver(
      entries => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            runCounter(entry.target);
            counterObserver.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.5 }
    );
    counters.forEach(counter => counterObserver.observe(counter));
  } else {
    counters.forEach(counter => {
      counter.textContent = counter.dataset.count;
    });
  }

  const tiltCards = Array.from(document.querySelectorAll(".tilt-card"));
  tiltCards.forEach(card => {
    card.addEventListener("pointermove", event => {
      if (prefersReduced) return;
      const rect = card.getBoundingClientRect();
      const x = (event.clientX - rect.left) / rect.width - 0.5;
      const y = (event.clientY - rect.top) / rect.height - 0.5;
      card.style.transform = `rotateX(${4 - y * 5}deg) rotateY(${-6 + x * 7}deg) translateY(-2px)`;
    });
    card.addEventListener("pointerleave", () => {
      card.style.transform = "";
    });
  });

  const canvas = document.getElementById("signalCanvas");
  if (!canvas || prefersReduced) return;

  const ctx = canvas.getContext("2d");
  let width = 0;
  let height = 0;
  let points = [];
  let animationFrame = 0;

  const resize = () => {
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = Math.floor(width * ratio);
    canvas.height = Math.floor(height * ratio);
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);

    const count = Math.max(42, Math.min(92, Math.floor(width / 18)));
    points = Array.from({ length: count }, () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.22,
      vy: (Math.random() - 0.5) * 0.22,
      r: Math.random() * 1.8 + 0.7
    }));
  };

  const draw = () => {
    ctx.clearRect(0, 0, width, height);
    ctx.globalCompositeOperation = "lighter";

    for (const point of points) {
      point.x += point.vx;
      point.y += point.vy;
      if (point.x < -20) point.x = width + 20;
      if (point.x > width + 20) point.x = -20;
      if (point.y < -20) point.y = height + 20;
      if (point.y > height + 20) point.y = -20;
    }

    for (let i = 0; i < points.length; i += 1) {
      for (let j = i + 1; j < points.length; j += 1) {
        const a = points[i];
        const b = points[j];
        const dx = a.x - b.x;
        const dy = a.y - b.y;
        const distance = Math.sqrt(dx * dx + dy * dy);
        if (distance < 132) {
          const alpha = (1 - distance / 132) * 0.25;
          ctx.strokeStyle = `rgba(83, 174, 255, ${alpha})`;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }
    }

    for (const point of points) {
      ctx.fillStyle = "rgba(139, 204, 255, 0.75)";
      ctx.beginPath();
      ctx.arc(point.x, point.y, point.r, 0, Math.PI * 2);
      ctx.fill();
    }

    animationFrame = requestAnimationFrame(draw);
  };

  window.addEventListener("resize", resize, { passive: true });
  resize();
  draw();

  window.addEventListener("pagehide", () => {
    cancelAnimationFrame(animationFrame);
  });
})();
