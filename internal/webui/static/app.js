// opnsense-exporter operator console — client runtime.
//
// Vanilla JS, no dependencies. Behaviour is guarded per page via
// document.body.dataset.page and every hook is existence-checked, so a page that
// lacks a given element is simply unaffected. The server-rendered templates emit
// the data-* hooks this script binds to (see status/cardinality/devices
// templates); this file never assumes an element is present.
(function () {
  'use strict';

  var page = (document.body && document.body.dataset && document.body.dataset.page) || '';

  function refreshMs() {
    var secs = window.__refreshSeconds;
    if (!secs || secs < 1) {
      secs = 5;
    }
    return secs * 1000;
  }

  // --- small helpers (mirror the Go render helpers) ---

  function healthClass(h) {
    if (h === 'healthy') { return 'ok'; }
    if (h === 'degraded') { return 'bad'; }
    return 'warn';
  }

  function stateClass(s) {
    if (s === 'ok') { return 'ok'; }
    if (s === 'failing') { return 'bad'; }
    return 'warn';
  }

  function pct(v) {
    if (v < 0) { return '—'; }
    return Math.round(v) + '%';
  }

  function setText(el, txt) {
    if (el) { el.textContent = String(txt); }
  }

  function findRow(name) {
    var rows = document.querySelectorAll('tr[data-name]');
    for (var i = 0; i < rows.length; i++) {
      if (rows[i].getAttribute('data-name') === name) {
        return rows[i];
      }
    }
    return null;
  }

  // --- status page live polling ---

  function applyRow(row) {
    var tr = findRow(row.Name);
    if (!tr) { return; }

    setText(tr.querySelector('[data-cell="state"]'), row.State);
    var dot = tr.querySelector('.dot');
    if (dot) { dot.className = 'dot dot-' + stateClass(row.State); }

    var succ = tr.querySelector('[data-cell="success"]');
    if (succ) {
      succ.textContent = pct(row.SuccessRate);
      succ.setAttribute('data-value', String(row.SuccessRate));
    }

    setText(tr.querySelector('[data-cell="runs"]'), row.Runs);
    setText(tr.querySelector('[data-cell="failures"]'), row.Failures);
    setText(tr.querySelector('[data-cell="consecutive"]'), row.Consecutive);
    setText(tr.querySelector('[data-cell="duration"]'), Number(row.LastDurationMs).toFixed(1));

    var spark = tr.querySelector('[data-cell="sparkline"]');
    if (spark) { spark.innerHTML = row.Sparkline || ''; }
    var out = tr.querySelector('[data-cell="outcomes"]');
    if (out) { out.innerHTML = row.Outcomes || ''; }

    setText(tr.querySelector('[data-cell="staleness"]'), row.Staleness || '');
  }

  function applyStatus(st) {
    if (!st) { return; }

    var badge = document.querySelector('[data-health]');
    if (badge) {
      badge.textContent = st.Health;
      badge.className = 'badge badge-' + healthClass(st.Health);
    }

    var age = document.querySelector('[data-scrape-age]');
    if (age) { age.textContent = 'as of ' + st.ScrapeAge; }

    if (st.Stats) {
      setText(document.querySelector('[data-tile="collectors"]'), st.Stats.ActiveCollectors);
      setText(document.querySelector('[data-tile="families"]'), st.Stats.MetricFamilies);
      setText(document.querySelector('[data-tile="series"]'), st.Stats.Series);
    }

    (st.Collectors || []).forEach(applyRow);
  }

  function pollStatus() {
    return fetch('/api/status.json', { headers: { Accept: 'application/json' } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(applyStatus)
      .catch(function () { /* transient; next tick retries */ });
  }

  // --- Run Now buttons ---

  function setBtn(btn, label, mod) {
    btn.textContent = label;
    btn.className = 'btn' + (mod ? ' btn-' + mod : '');
  }

  function wireTriggers() {
    document.addEventListener('click', function (e) {
      var btn = e.target.closest ? e.target.closest('[data-collector]') : null;
      if (!btn || btn.disabled) { return; }
      e.preventDefault();

      var name = btn.getAttribute('data-collector');
      var orig = btn.textContent;
      btn.disabled = true;
      setBtn(btn, 'Running…', 'running');

      fetch('/api/collectors/trigger?collector=' + encodeURIComponent(name), { method: 'POST' })
        .then(function (r) {
          return r.json().catch(function () { return {}; }).then(function (body) {
            return { code: r.status, body: body };
          });
        })
        .then(function (res) {
          if (res.code === 409) {
            setBtn(btn, 'Busy', 'busy');
          } else if (res.body && res.body.status === 'ok') {
            setBtn(btn, 'Ran (ok)', 'ok');
            pollStatus();
          } else {
            setBtn(btn, 'Failed', 'failed');
          }
        })
        .catch(function () { setBtn(btn, 'Failed', 'failed'); })
        .then(function () {
          setTimeout(function () {
            setBtn(btn, orig, '');
            btn.disabled = false;
          }, 4000);
        });
    });
  }

  // --- filters ---

  function resolveTable(target) {
    if (!target) { return null; }
    var byData = document.querySelector('[data-table="' + target + '"]');
    if (byData) { return byData; }
    try {
      var bySel = document.querySelector(target);
      if (bySel) { return bySel; }
    } catch (err) { /* not a valid selector; fall through */ }
    return document.getElementById(target);
  }

  function rowsOf(table) {
    var body = table.tBodies && table.tBodies[0];
    return body ? Array.prototype.slice.call(body.rows) : [];
  }

  function rowHaystack(tr) {
    var parts = [tr.getAttribute('data-name') || ''];
    tr.querySelectorAll('[data-value]').forEach(function (c) {
      parts.push(c.getAttribute('data-value') || '');
    });
    return parts.join(' ').toLowerCase();
  }

  function wireFilters() {
    document.querySelectorAll('input[data-filter-target]').forEach(function (input) {
      var table = resolveTable(input.getAttribute('data-filter-target'));
      if (!table) { return; }
      input.addEventListener('input', function () {
        var q = input.value.trim().toLowerCase();
        rowsOf(table).forEach(function (tr) {
          if (tr.querySelector('.empty')) { return; }
          var match = !q || rowHaystack(tr).indexOf(q) !== -1;
          tr.style.display = match ? '' : 'none';
        });
      });
    });
  }

  // --- sortable columns ---

  function cellKey(tr, col) {
    var c = tr.cells[col];
    if (!c) { return ''; }
    var v = c.getAttribute('data-sort');
    if (v === null) { v = c.getAttribute('data-value'); }
    if (v === null) { v = c.textContent; }
    return v == null ? '' : v;
  }

  function columnSortable(body, col) {
    var rows = body.rows;
    for (var i = 0; i < rows.length; i++) {
      var c = rows[i].cells[col];
      if (c && c.hasAttribute('data-sort')) { return true; }
    }
    return false;
  }

  function sortTable(table, col, asc) {
    var body = table.tBodies[0];
    var rows = Array.prototype.slice.call(body.rows).filter(function (r) {
      return !r.querySelector('.empty');
    });
    rows.sort(function (a, b) {
      var av = cellKey(a, col);
      var bv = cellKey(b, col);
      var an = parseFloat(av);
      var bn = parseFloat(bv);
      var cmp;
      if (!isNaN(an) && !isNaN(bn) && String(av).trim() !== '' && String(bv).trim() !== '') {
        cmp = an - bn;
      } else {
        cmp = String(av).toLowerCase().localeCompare(String(bv).toLowerCase());
      }
      return asc ? cmp : -cmp;
    });
    rows.forEach(function (r) { body.appendChild(r); });
  }

  function wireSort() {
    document.querySelectorAll('table.grid').forEach(function (table) {
      var body = table.tBodies && table.tBodies[0];
      var head = table.tHead && table.tHead.rows[0];
      if (!body || !head) { return; }
      var ths = head.cells;
      for (var col = 0; col < ths.length; col++) {
        if (!columnSortable(body, col)) { continue; }
        var th = ths[col];
        th.classList.add('sortable');
        th.setAttribute('data-sort', ''); // affordance hook for CSS th[data-sort]
        (function (th, col) {
          th.addEventListener('click', function () {
            var asc = th.getAttribute('data-dir') !== 'asc';
            sortTable(table, col, asc);
            for (var i = 0; i < ths.length; i++) { ths[i].removeAttribute('data-dir'); }
            th.setAttribute('data-dir', asc ? 'asc' : 'desc');
          });
        }(th, col));
      }
    });
  }

  // --- bootstrap ---

  function init() {
    wireTriggers();
    wireFilters();
    wireSort();

    // Status is the live page: its JSON twin carries the full model, so we poll
    // it and update in place. Cardinality/devices keep their filter/sort state
    // client-side and their JSON twins carry no freshness marker, so they are
    // driven by filters/sort only and refresh on reload.
    if (page === 'status') {
      pollStatus();
      setInterval(pollStatus, refreshMs());
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
}());
