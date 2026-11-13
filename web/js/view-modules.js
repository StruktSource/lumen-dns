/* Modules: big optional features. Every module is off until an administrator switches it on. */
(() => {
'use strict';
const L = window.L, h = L.h;
const NS = 'http://www.w3.org/2000/svg';
const sv = (tag, a = {}, ...k) => { const e = document.createElementNS(NS, tag); for (const [x, y] of Object.entries(a)) e.setAttribute(x, y); k.forEach(c => e.append(c)); return e; };

/* The catalog. `page` is the console page the module adds to the sidebar while it is on. */
L.MODULES = [
  { id: 'traffic-map', page: 'trafficmap', name: 'Traffic map', icon: 'map',
    text: 'An interactive tree of your DNS traffic: Lumen at the top, then every top-level domain, then the domains and services under it. See at a glance where queries go and what gets blocked.',
    needs: 'Needs query history. Turn it on under Activity.' },
  { id: 'dhcp', page: 'dhcp', name: 'DHCP', icon: 'server',
    text: 'The DHCP server for IPv4 and IPv6 built into Lumen. Devices that get an address also get a DNS name, so you can reach them by name. See your networks and every lease at a glance.',
    needs: 'Needs dhcp.enabled in the configuration. Lumen never hands out addresses on its own.' }];

L.loadModules = async () => { L.S.modules = await L.api('GET', '/api/modules'); L.S.modulesAt = Date.now(); };
L.moduleOn = id => !!L.S.modules?.enabled?.includes(id);

let busy = '';

const toggle = async (m, on) => {
  busy = m.id; L.rerender();
  try { L.S.modules = await L.api('PUT', '/api/modules', { id: m.id, enabled: on }); L.S.modulesAt = Date.now(); if (!on) L.stopModule?.(m.id); L.toast(L.t(on ? '{name} is on.' : '{name} is off.', { name: L.t(m.name) })); }
  catch (e) { L.toast(e.message, 'bad'); }
  busy = ''; L.rerender();
};

/* A small drawing of what the module looks like, so the card says more than a sentence. */
const preview = id => {
  if (id === 'dhcp') {
    const s = sv('svg', { class: 'mod-art', viewBox: '0 0 240 120', 'aria-hidden': 'true' });
    s.append(sv('path', { class: 'mod-edge', d: 'M120 34V52M120 52H48V76M120 52V76M120 52H192V76', fill: 'none', pathLength: '1' }));
    s.append(sv('rect', { class: 'mod-n root', x: 92, y: 14, width: 56, height: 20 }));
    [48, 120, 192].forEach(x => s.append(sv('rect', { class: 'mod-n leaf', x: x - 22, y: 76, width: 44, height: 16 })));
    return s;
  }
  if (id !== 'traffic-map') return null;
  const s = sv('svg', { class: 'mod-art', viewBox: '0 0 240 120', 'aria-hidden': 'true' });
  const edge = d => s.append(sv('path', { class: 'mod-edge', d, fill: 'none', pathLength: '1' }));
  edge('M120 26V44M120 44H48V62M120 44H120V62M120 44H192V62'); edge('M48 76V90H62M48 90V104H62M192 76V90H206');
  [[120, 14, 'mod-n root'], [48, 70, 'mod-n'], [120, 70, 'mod-n'], [192, 70, 'mod-n bad']].forEach(([x, y, c]) => s.append(sv('rect', { class: c, x: x - 22, y: y - 8, width: 44, height: 16 })));
  [[70, 90], [70, 104], [214, 90]].forEach(([x, y]) => s.append(sv('rect', { class: 'mod-n leaf', x, y: y - 6, width: 34, height: 12 })));
  return s;
};

L.views.modules = () => {
  const admin = L.can('admin'), enabled = L.S.modules?.enabled || [];
  const cards = L.MODULES.map(m => {
    const on = enabled.includes(m.id);
    return h('article', { class: 'card mod' + (on ? ' on' : ''), 'aria-labelledby': 'mod-' + m.id },
      h('div', { class: 'mod-top' }, preview(m.id)),
      h('div', { class: 'card-b stack' },
        h('div', { class: 'row', style: 'justify-content:space-between' }, h('h3', { id: 'mod-' + m.id, class: 'mod-name' }, L.ic(m.icon), m.name), h('span', { class: 'pill ' + (on ? 'ok' : 'off') }, on ? 'On' : 'Off')),
        h('p', { class: 'muted', style: 'margin:0' }, m.text),
        h('div', { class: 'hint' }, m.needs),
        h('div', { class: 'row', style: 'justify-content:space-between' },
          admin ? h('label', { class: 'switch' }, h('input', { type: 'checkbox', checked: on, disabled: !!busy, 'aria-label': L.t(on ? 'Turn off {name}' : 'Turn on {name}', { name: L.t(m.name) }), onchange: e => toggle(m, e.target.checked) }), h('i'), on ? 'On' : 'Off')
            : h('span', { class: 'hint' }, 'Only an administrator can turn modules on or off.'),
          on ? h('button', { class: 'btn primary', onclick: () => L.go(m.page) }, 'Open', L.ic('arrow')) : null)));
  });
  return [L.pageHead('Modules', 'Big, optional features. Each one is off until you turn it on, and nothing runs for a module that is off.'),
    h('div', { class: 'grid g3' }, cards),
    h('p', { class: 'hint', style: 'margin-top:18px' }, 'More modules will appear here as they are added.')];
};
})();
