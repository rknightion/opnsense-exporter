/* SEO enhancements for OPNsense Exporter documentation */

document.addEventListener('DOMContentLoaded', function() {
  addStructuredData();
  enhanceMetaTags();
  addOpenGraphTags();
  addTwitterCardTags();
  addCanonicalURL();
});

// Add JSON-LD structured data
function addStructuredData() {
  const structuredData = {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    "name": "OPNsense Exporter",
    "applicationCategory": "Network Monitoring Software",
    "operatingSystem": "Linux, Docker, FreeBSD",
    "description": "A comprehensive Prometheus exporter for OPNsense firewalls providing 320+ metrics across 26 collectors for firewall monitoring, network diagnostics, and system observability",
    "url": "https://m7kni.io/opnsense-exporter/",
    "downloadUrl": "https://github.com/rknightion/opnsense-exporter",
    "softwareVersion": "latest",
    "programmingLanguage": "Go",
    "license": "https://github.com/rknightion/opnsense-exporter/blob/main/LICENSE",
    "author": {
      "@type": "Person",
      "name": "Rob Knighton",
      "url": "https://github.com/rknightion"
    },
    "maintainer": {
      "@type": "Person",
      "name": "Rob Knighton",
      "url": "https://github.com/rknightion"
    },
    "codeRepository": "https://github.com/rknightion/opnsense-exporter",
    "programmingLanguage": [
      "Go",
      "Docker",
      "YAML"
    ],
    "runtimePlatform": [
      "Docker",
      "Kubernetes",
      "Linux",
      "FreeBSD"
    ],
    "applicationSubCategory": [
      "Firewall Monitoring",
      "Prometheus Exporter",
      "OPNsense",
      "Observability",
      "Network Security"
    ],
    "offers": {
      "@type": "Offer",
      "price": "0",
      "priceCurrency": "USD"
    },
    "screenshot": "https://m7kni.io/opnsense-exporter/assets/social-card.png",
    "featureList": [
      "26 specialized collectors for OPNsense subsystems",
      "320+ Prometheus metrics",
      "Concurrent collection via goroutines",
      "Docker and Kubernetes deployment",
      "File-based secret support",
      "High-availability CARP monitoring",
      "Comprehensive firewall PF statistics",
      "Production-ready monitoring"
    ]
  };

  // Add documentation-specific structured data
  const docData = {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "headline": document.title,
    "description": document.querySelector('meta[name="description"]')?.content || "OPNsense Exporter documentation",
    "url": window.location.href,
    "datePublished": document.querySelector('meta[name="date"]')?.content,
    "dateModified": document.querySelector('meta[name="git-revision-date-localized"]')?.content,
    "author": {
      "@type": "Person",
      "name": "Rob Knighton"
    },
    "publisher": {
      "@type": "Organization",
      "name": "OPNsense Exporter",
      "url": "https://m7kni.io/opnsense-exporter/"
    },
    "mainEntityOfPage": {
      "@type": "WebPage",
      "@id": window.location.href
    },
    "articleSection": getDocumentationSection(),
    "keywords": getPageKeywords(),
    "about": {
      "@type": "SoftwareApplication",
      "name": "OPNsense Exporter"
    }
  };

  // Insert structured data
  const script1 = document.createElement('script');
  script1.type = 'application/ld+json';
  script1.textContent = JSON.stringify(structuredData);
  document.head.appendChild(script1);

  const script2 = document.createElement('script');
  script2.type = 'application/ld+json';
  script2.textContent = JSON.stringify(docData);
  document.head.appendChild(script2);
}

// Enhance existing meta tags
function enhanceMetaTags() {
  // Add robots meta if not present
  if (!document.querySelector('meta[name="robots"]')) {
    addMetaTag('name', 'robots', 'index, follow, max-snippet:-1, max-image-preview:large, max-video-preview:-1');
  }

  // Add language meta
  addMetaTag('name', 'language', 'en');

  // Add content type
  addMetaTag('http-equiv', 'Content-Type', 'text/html; charset=utf-8');

  // Add viewport if not present (should be handled by Material theme)
  if (!document.querySelector('meta[name="viewport"]')) {
    addMetaTag('name', 'viewport', 'width=device-width, initial-scale=1');
  }

  // Add keywords based on page content
  const keywords = getPageKeywords();
  if (keywords) {
    addMetaTag('name', 'keywords', keywords);
  }

  // Add article tags for documentation pages
  if (isDocumentationPage()) {
    addMetaTag('name', 'article:tag', 'prometheus');
    addMetaTag('name', 'article:tag', 'monitoring');
    addMetaTag('name', 'article:tag', 'opnsense');
    addMetaTag('name', 'article:tag', 'firewall-monitoring');
  }
}

// Add Open Graph tags
function addOpenGraphTags() {
  const title = document.title || 'OPNsense Exporter';
  const description = document.querySelector('meta[name="description"]')?.content ||
    'Comprehensive Prometheus exporter for OPNsense firewalls with 320+ metrics';
  const url = window.location.href;
  const siteName = 'OPNsense Exporter Documentation';

  addMetaTag('property', 'og:type', 'website');
  addMetaTag('property', 'og:site_name', siteName);
  addMetaTag('property', 'og:title', title);
  addMetaTag('property', 'og:description', description);
  addMetaTag('property', 'og:url', url);
  addMetaTag('property', 'og:locale', 'en_US');
  addMetaTag('property', 'og:image', 'https://m7kni.io/opnsense-exporter/assets/social-card.png');
  addMetaTag('property', 'og:image:width', '1200');
  addMetaTag('property', 'og:image:height', '630');
  addMetaTag('property', 'og:image:alt', 'OPNsense Exporter - Prometheus metrics for OPNsense firewalls');
}

// Add Twitter Card tags
function addTwitterCardTags() {
  const title = document.title || 'OPNsense Exporter';
  const description = document.querySelector('meta[name="description"]')?.content ||
    'Comprehensive Prometheus exporter for OPNsense firewalls with 320+ metrics';

  addMetaTag('name', 'twitter:card', 'summary_large_image');
  addMetaTag('name', 'twitter:title', title);
  addMetaTag('name', 'twitter:description', description);
  addMetaTag('name', 'twitter:image', 'https://m7kni.io/opnsense-exporter/assets/social-card.png');
  addMetaTag('name', 'twitter:creator', '@rknightion');
  addMetaTag('name', 'twitter:site', '@rknightion');
}

// Add canonical URL
function addCanonicalURL() {
  if (!document.querySelector('link[rel="canonical"]')) {
    const canonical = document.createElement('link');
    canonical.rel = 'canonical';
    canonical.href = window.location.href;
    document.head.appendChild(canonical);
  }
}

// Helper functions
function addMetaTag(attribute, name, content) {
  if (!document.querySelector(`meta[${attribute}="${name}"]`)) {
    const meta = document.createElement('meta');
    meta.setAttribute(attribute, name);
    meta.content = content;
    document.head.appendChild(meta);
  }
}

function getDocumentationSection() {
  const path = window.location.pathname;
  if (path.includes('/metrics/')) return 'Metrics Reference';
  if (path.includes('/collectors/')) return 'Collector Reference';
  if (path.includes('/configuration/')) return 'Configuration';
  if (path.includes('/deployment/')) return 'Deployment';
  if (path.includes('/security/')) return 'Security';
  if (path.includes('/architecture/')) return 'Architecture';
  return 'Documentation';
}

function getPageKeywords() {
  const path = window.location.pathname;
  const title = document.title.toLowerCase();
  const content = document.body.textContent.toLowerCase();

  let keywords = ['opnsense', 'prometheus', 'exporter', 'monitoring', 'firewall'];

  // Add path-specific keywords
  if (path.includes('/metrics/')) keywords.push('metrics', 'telemetry', 'observability');
  if (path.includes('/collectors/')) keywords.push('collectors', 'data collection', 'api');
  if (path.includes('/configuration/')) keywords.push('configuration', 'environment variables', 'setup');
  if (path.includes('/deployment/')) keywords.push('deployment', 'docker', 'kubernetes', 'production');
  if (path.includes('/getting-started/')) keywords.push('installation', 'quick start', 'tutorial');

  // Add subsystem keywords if mentioned
  if (content.includes('wireguard')) keywords.push('wireguard', 'vpn');
  if (content.includes('ipsec')) keywords.push('ipsec', 'vpn', 'tunnel');
  if (content.includes('unbound')) keywords.push('dns', 'unbound', 'resolver');
  if (content.includes('carp')) keywords.push('carp', 'high-availability', 'failover');
  if (content.includes('pf') || content.includes('packet filter')) keywords.push('pf', 'packet-filter', 'freebsd');
  if (content.includes('dhcp')) keywords.push('dhcp', 'leases', 'dnsmasq', 'kea');

  return keywords.join(', ');
}

function isDocumentationPage() {
  return !window.location.pathname.endsWith('/') ||
         window.location.pathname.includes('/docs/');
}
