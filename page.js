// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 BOBI SAS, France
// Auteur : Cyril Mazouer, pour le compte de BOBI SAS
// Distribué sous licence GNU GPL v3 (ou ultérieure) ; voir le fichier LICENSE.
//
// Tests réseau — UI de l'outil (runtime=inprocess). Les sondes, l'historique et la
// surveillance sont dans backend.py : cette page décrit les formulaires, appelle l'API et
// met en forme des résultats STRUCTURÉS (jamais du texte de `ping` à relire).
window.BTTools = window.BTTools || {};
window.BTTools.net_tests = (function () {
    let EL = null, CTX = null;
    let INFO = null, GRANTED = new Set(), ADMIN = false;
    let kind = "ping";
    let dernier = null;              // dernier résultat ponctuel (pour « Surveiller ce test »)
    let monEdit = null;              // contrôle en cours d'édition (null = création)
    let timer = null;
    let ouverts = new Set();         // lignes d'historique dépliées

    const esc = (window.BT && BT.esc) || ((s) => String(s == null ? "" : s)
        .replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])));
    const $ = (sel) => EL.querySelector(sel);
    const $$ = (sel) => Array.from(EL.querySelectorAll(sel));
    const toast = (m, t) => (CTX && CTX.toast ? CTX.toast(m, t) : null);

    // ── Description des tests ───────────────────────────────────
    // `mon` : champ propre à la surveillance (seuil d'alerte) ; `wide` : pleine largeur.
    const KINDS = {
        ping: { label: "Ping", fields: [
            { k: "target", l: "Cible", t: "target", ph: "ex. 10.1.30.2 ou nom d'hôte", wide: true },
            { k: "count", l: "Paquets", t: "number", d: 4, min: 1, max: 50 },
            { k: "timeout", l: "Délai par paquet (s)", t: "number", d: 1, step: 0.1 },
            { k: "interval", l: "Intervalle (s)", t: "number", d: 0.25, step: 0.05 },
            { k: "size", l: "Charge (octets)", t: "number", d: 32, min: 0, max: 1400 }] },
        traceroute: { label: "Traceroute", fields: [
            { k: "target", l: "Cible", t: "target", ph: "ex. 10.1.30.2", wide: true },
            { k: "max_hops", l: "Sauts maxi", t: "number", d: 20, min: 1, max: 40 },
            { k: "tries", l: "Essais par saut", t: "number", d: 2, min: 1, max: 5 },
            { k: "timeout", l: "Délai (s)", t: "number", d: 1.5, step: 0.1 }] },
        tcp: { label: "Ports TCP", fields: [
            { k: "target", l: "Cible", t: "target", ph: "ex. 10.1.99.11", wide: true },
            { k: "ports", l: "Ports", t: "text", d: "22 80 443", ph: "ex. 22 80 443" },
            { k: "timeout", l: "Délai (s)", t: "number", d: 2, step: 0.1 }] },
        tls: { label: "Certificat TLS", fields: [
            { k: "target", l: "Cible", t: "target", ph: "ex. vault.exemple.fr", wide: true },
            { k: "port", l: "Port", t: "number", d: 443, min: 1, max: 65535 },
            { k: "sni", l: "Nom présenté (SNI)", t: "text", ph: "par défaut : la cible" },
            { k: "timeout", l: "Délai (s)", t: "number", d: 5, step: 0.5 },
            { k: "warn_days", l: "Alerter sous (jours)", t: "number", d: 14, min: 0, mon: true }] },
        http: { label: "HTTP", fields: [
            { k: "url", l: "URL", t: "text", ph: "ex. http://10.1.10.20/ ou https://…", wide: true, list: true },
            { k: "method", l: "Méthode", t: "select", d: "GET", opts: ["GET", "HEAD", "OPTIONS"] },
            { k: "timeout", l: "Délai (s)", t: "number", d: 5, step: 0.5 },
            { k: "verify", l: "Vérifier le certificat", t: "check", d: false },
            { k: "follow", l: "Suivre les redirections", t: "check", d: true },
            { k: "expect_status", l: "Code attendu", t: "number", ph: "défaut : < 400", mon: true }] },
        dns: { label: "DNS", fields: [
            { k: "name", l: "Nom (ou IP pour PTR)", t: "text", ph: "ex. bobitools.exemple.fr", wide: true },
            { k: "type", l: "Type", t: "select", d: "A", opts: () => (INFO && INFO.dns_types) || ["A"] },
            { k: "resolver", l: "Résolveur", t: "text", ph: "défaut : celui du serveur" },
            { k: "timeout", l: "Délai (s)", t: "number", d: 3, step: 0.5 },
            { k: "expect", l: "Réponse attendue (contient)", t: "text", ph: "ex. 10.1.10.250", mon: true }] },
        multicast: { label: "Multicast", perm: "multicast", fields: [
            { k: "group", l: "Groupe", t: "text", ph: "ex. 239.4.1.1" },
            { k: "port", l: "Port UDP", t: "number", d: 5004, min: 1, max: 65535 },
            { k: "seconds", l: "Durée d'écoute (s)", t: "number", d: 5, min: 1, max: 60 },
            { k: "interface", l: "Interface", t: "select", d: "", opts: () => [["", "par défaut (route)"]]
                .concat(((INFO && INFO.interfaces) || []).map(i => [i.ip, i.name + " — " + i.ip])) }] },
        scan: { label: "Balayage", perm: "scan", fields: [
            { k: "cidr", l: "Plage", t: "text", ph: "ex. 10.1.99.0/24", wide: true },
            { k: "ports", l: "Ports (8 au plus)", t: "text", ph: "ex. 22 80 443" },
            { k: "timeout", l: "Délai (s)", t: "number", d: 1, step: 0.1 }] },
    };
    const MON_KINDS = ["ping", "tcp", "http", "dns", "tls"];

    const AVERTISSEMENTS = {
        multicast: "<b>Rejoindre un groupe n'est pas une simple observation.</b> Le serveur envoie un " +
            "IGMP join : le switch lui livre alors le flux pendant toute l'écoute. Une essence vidéo " +
            "ST 2110 pèse plusieurs Gb/s — de quoi saturer une interface d'administration. Choisissez " +
            "l'interface du fabric et gardez une durée courte.",
        scan: "Le balayage envoie un ping (et les ports demandés) à <b>chaque</b> adresse de la plage. " +
            "Un hôte muet au ping n'est pas forcément absent : beaucoup filtrent l'écho, d'où l'intérêt " +
            "d'ajouter un port connu (22, 80…).",
    };

    const permis = (k) => {
        const p = KINDS[k] && KINDS[k].perm;
        return !p || ADMIN || GRANTED.has(p);
    };
    const peut = (perm) => ADMIN || GRANTED.has(perm);

    // ── Utilitaires d'affichage ─────────────────────────────────
    const ms = (v) => v == null ? "—" : (v < 10 ? v.toFixed(2) : Math.round(v)) + " ms";
    const quand = (t) => {
        if (!t) return "—";
        const d = new Date(t * 1000), now = new Date();
        const hh = d.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
        return d.toDateString() === now.toDateString() ? hh
            : d.toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit" }) + " " + hh;
    };
    const duree = (t) => {
        if (!t) return "—";
        const s = Math.max(0, Math.round(Date.now() / 1000 - t));
        if (s < 60) return s + " s";
        if (s < 3600) return Math.round(s / 60) + " min";
        if (s < 86400) return Math.floor(s / 3600) + " h " + String(Math.round((s % 3600) / 60)).padStart(2, "0");
        return Math.floor(s / 86400) + " j";
    };
    const intervalle = (s) => s % 3600 === 0 ? (s / 3600) + " h" : s % 60 === 0 ? (s / 60) + " min" : s + " s";
    const stat = (l, v) => `<div class="nt-stat"><span>${esc(l)}</span><b>${esc(v)}</b></div>`;
    const kv = (rows) => '<table class="nt-table nt-kv"><tbody>' + rows.filter(r => r[1] !== undefined && r[1] !== null && r[1] !== "")
        .map(r => `<tr><td>${esc(r[0])}</td><td class="nt-wrapcell">${r[2] ? r[1] : esc(r[1])}</td></tr>`).join("") + "</tbody></table>";

    // ── Formulaire ──────────────────────────────────────────────
    function champHtml(f, val, prefix, pourMon) {
        if (f.mon && !pourMon) return "";
        const id = prefix + f.k;
        const v = val !== undefined ? val : (f.d !== undefined ? f.d : "");
        const cls = "nt-field" + (f.wide ? " is-wide" : "") + (f.t === "check" ? " is-check" : "");
        if (f.t === "check") {
            return `<label class="${cls}"><input type="checkbox" id="${id}" data-k="${f.k}" ${v ? "checked" : ""}><span>${esc(f.l)}</span></label>`;
        }
        let input;
        if (f.t === "select") {
            const opts = (typeof f.opts === "function" ? f.opts() : f.opts)
                .map(o => Array.isArray(o) ? o : [o, o])
                .map(([ov, ol]) => `<option value="${esc(ov)}" ${String(ov) === String(v) ? "selected" : ""}>${esc(ol)}</option>`).join("");
            input = `<select id="${id}" data-k="${f.k}">${opts}</select>`;
        } else {
            const type = f.t === "number" ? "number" : "text";
            const attrs = [f.min !== undefined ? `min="${f.min}"` : "", f.max !== undefined ? `max="${f.max}"` : "",
                f.step !== undefined ? `step="${f.step}"` : (f.t === "number" ? 'step="any"' : ""),
                (f.t === "target" || f.list) ? 'list="nt-targets"' : ""].join(" ");
            input = `<input type="${type}" id="${id}" data-k="${f.k}" value="${esc(v)}" placeholder="${esc(f.ph || "")}" ${attrs}>`;
        }
        return `<label class="${cls}"><span>${esc(f.l)}</span>${input}</label>`;
    }

    function lireChamps(root, k) {
        const out = {};
        KINDS[k].fields.forEach(f => {
            const el = root.querySelector(`[data-k="${f.k}"]`);
            if (!el) return;
            if (f.t === "check") out[f.k] = el.checked;
            else if (f.t === "number") { if (el.value !== "") out[f.k] = Number(el.value); }
            else { const s = el.value.trim(); if (s !== "") out[f.k] = s; }
        });
        return out;
    }

    function dessinerKinds() {
        $("#nt-kinds").innerHTML = Object.entries(KINDS).map(([k, d]) => {
            const ok = permis(k);
            return `<button type="button" class="btn nt-kind ${k === kind ? "is-on" : ""}" data-kind="${k}" ` +
                `${ok ? "" : 'disabled title="Réservé aux administrateurs (permission « ' + esc(d.perm) + ' »)"'}>${esc(d.label)}</button>`;
        }).join("");
    }

    function dessinerForm(valeurs) {
        $("#nt-fields").innerHTML = KINDS[kind].fields.map(f => champHtml(f, valeurs ? valeurs[f.k] : undefined, "nt-f-", false)).join("");
        const w = AVERTISSEMENTS[kind];
        $("#nt-warn").hidden = !w;
        $("#nt-warn").innerHTML = w || "";
        const ok = permis(kind);
        $("#nt-run").disabled = !ok;
        $("#nt-denied").hidden = ok;
        $("#nt-denied").textContent = ok ? "" : "Ce test est réservé aux administrateurs.";
    }

    async function chargerCibles() {
        try {
            const r = await CTX.api("targets");
            const opts = [];
            (r.sources || []).forEach(s => (s.items || []).forEach(it => {
                opts.push(`<option value="${esc(it.host)}">${esc(it.label + (it.detail ? " — " + it.detail : "") + " · " + s.label)}</option>`);
            }));
            $("#nt-targets").innerHTML = opts.join("");
        } catch (e) { /* sans inventaire, la saisie libre reste possible */ }
    }

    // ── Lancer un test ──────────────────────────────────────────
    async function lancer(ev) {
        ev.preventDefault();
        const p = lireChamps($("#nt-form"), kind);
        $("#nt-run").disabled = true;
        $("#nt-busy").hidden = false;
        $("#nt-result").hidden = true;
        try {
            const r = await CTX.api("probe/" + kind, { body: p });
            dernier = r;
            $("#nt-result").innerHTML = rendreResultat(r, true);
            $("#nt-result").hidden = false;
        } catch (e) {
            if (!e.rightsShown) toast(e.message, "error");
        } finally {
            $("#nt-run").disabled = !permis(kind);
            $("#nt-busy").hidden = true;
        }
    }

    function rendreResultat(h, actions) {
        const tete = `<div class="nt-verdict"><b class="${h.ok ? "nt-ok" : "nt-ko"}">${h.ok ? "✔" : "✖"} ${esc(h.summary || "")}</b>` +
            `<span class="meta">${esc(KINDS[h.kind] ? KINDS[h.kind].label : h.kind)} · ${esc(h.label || "")} · ${esc(String(h.seconds))} s</span></div>`;
        const r = h.result;
        let corps = "";
        if (r) {
            try { corps = (RENDUS[h.kind] || (() => ""))(r); } catch (e) { corps = ""; }
        }
        const brut = r ? `<details class="nt-raw"><summary>Données brutes</summary><pre>${esc(JSON.stringify(r, null, 2))}</pre></details>` : "";
        const act = actions && MON_KINDS.includes(h.kind) && peut("monitor.manage")
            ? '<div class="nt-result-actions"><button class="btn btn-sm" type="button" data-act="watch">Surveiller ce test</button></div>' : "";
        return tete + corps + brut + act;
    }

    const RENDUS = {
        ping(r) {
            const max = Math.max(1, ...r.attempts.filter(a => a.ok).map(a => a.ms));
            const bars = r.attempts.map(a => a.ok
                ? `<i style="height:${Math.max(4, Math.round(100 * a.ms / max))}%" title="#${a.seq} : ${esc(ms(a.ms))}"></i>`
                : `<i class="is-lost" title="#${a.seq} : ${esc(a.error || "perdu")}"></i>`).join("");
            return `<div class="nt-stats">${stat("Adresse", r.ip)}${stat("Reçus", r.received + " / " + r.sent)}` +
                `${stat("Perte", r.loss_pct + " %")}${stat("Min", ms(r.min_ms))}${stat("Moyenne", ms(r.avg_ms))}` +
                `${stat("Max", ms(r.max_ms))}${stat("Gigue", ms(r.jitter_ms))}</div><div class="nt-bars">${bars}</div>`;
        },
        traceroute(r) {
            return '<table class="nt-table"><thead><tr><th>Saut</th><th>Adresse</th><th>Nom</th><th>Temps</th></tr></thead><tbody>' +
                r.hops.map(h => `<tr><td class="num">${h.ttl}</td><td class="num">${esc(h.ip || "*")}</td>` +
                    `<td>${esc(h.hostname || "")}</td><td class="num">${h.ms.map(x => x == null ? "*" : esc(ms(x))).join(" · ")}</td></tr>`).join("") +
                "</tbody></table>" + (r.reached ? "" : '<p class="meta">Un saut muet (« * ») n\'est pas une panne : beaucoup de routeurs ne répondent pas aux TTL expirés.</p>');
        },
        tcp(r) {
            const etat = { open: ["nt-ok", "ouvert"], closed: ["nt-ko", "refusé — l'hôte répond, rien n'écoute"],
                filtered: ["nt-ko", "filtré — aucune réponse (pare-feu, ou hôte absent)"], error: ["nt-ko", "erreur"] };
            return `<div class="nt-stats">${stat("Adresse", r.ip)}${r.hostname ? stat("Nom", r.hostname) : ""}</div>` +
                '<table class="nt-table"><thead><tr><th>Port</th><th>État</th><th>Établissement</th></tr></thead><tbody>' +
                r.ports.map(p => { const e = etat[p.state] || ["", p.state];
                    return `<tr><td class="num">${p.port}</td><td class="${e[0]}">${esc(e[1])}${p.detail && p.state === "error" ? " — " + esc(p.detail) : ""}</td><td class="num">${esc(ms(p.ms))}</td></tr>`; }).join("") +
                "</tbody></table>";
        },
        tls(r) {
            const c = r.cert || {};
            const j = r.days_left;
            return kv([["Adresse", r.ip + ":" + r.port], ["SNI", r.sni],
                ["Sujet (CN)", (c.subject || {}).commonName], ["Émetteur", (c.issuer || {}).commonName || (c.issuer || {}).organizationName],
                ["Valide du", c.not_before], ["Valide jusqu'au", c.not_after],
                ["Reste", j == null ? "—" : `<b class="${j < 0 ? "nt-ko" : j < 14 ? "nt-ko" : "nt-ok"}">${esc(j < 0 ? "EXPIRÉ depuis " + (-j) + " j" : j + " jours")}</b>`, true],
                ["Noms couverts", (c.san || []).join(", ")], ["Protocole", r.tls_version], ["Chiffrement", r.cipher],
                ["Chaîne reconnue", r.verified ? '<span class="nt-ok">oui</span>' : '<span class="nt-ko">non — un navigateur avertirait</span>', true],
                ["Poignée de main", ms(r.ms)], ["Série", c.serial]]);
        },
        http(r) {
            const red = r.redirects.length ? '<table class="nt-table"><thead><tr><th>Code</th><th>URL</th><th>Vers</th></tr></thead><tbody>' +
                r.redirects.map(x => `<tr><td class="num">${x.status}</td><td class="nt-wrapcell">${esc(x.url)}</td><td class="nt-wrapcell">${esc(x.location || "")}</td></tr>`).join("") +
                "</tbody></table>" : "";
            return `<div class="nt-stats">${stat("Code", r.status + " " + (r.reason || ""))}${stat("Temps", ms(r.ms))}${stat("Taille", r.size + " o")}` +
                `${stat("Certificat vérifié", r.verified ? "oui" : "non")}</div>` + kv([["URL finale", r.final_url]]) + red +
                kv(Object.entries(r.headers || {}));
        },
        dns(r) {
            return `<div class="nt-stats">${stat("Statut", r.status)}${stat("Temps", ms(r.ms))}${stat("TTL", r.ttl == null ? "—" : r.ttl + " s")}` +
                `${stat("Résolveur", (r.answered_by || (r.resolvers || []).join(", ")) || "—")}</div>` +
                (r.records.length ? '<table class="nt-table"><tbody>' + r.records.map(x => `<tr><td class="nt-mono">${esc(x)}</td></tr>`).join("") + "</tbody></table>"
                    : `<p class="meta">${esc(r.detail || "Aucun enregistrement.")}</p>`) +
                (r.query !== r.name ? `<p class="meta">Question posée : <span class="nt-mono">${esc(r.query)}</span></p>` : "");
        },
        multicast(r) {
            return `<div class="nt-stats">${stat("Groupe", r.group + ":" + r.port)}${stat("Interface", r.interface || "par défaut")}` +
                `${stat("Paquets", r.packets)}${stat("Débit", r.mbps + " Mb/s")}${stat("Paquets/s", r.pps)}${stat("Durée", r.seconds + " s")}</div>` +
                (r.sources.length ? '<table class="nt-table"><thead><tr><th>Source</th><th>Paquets</th><th>Octets</th></tr></thead><tbody>' +
                    r.sources.map(s => `<tr><td class="num">${esc(s.ip)}</td><td class="num">${s.packets}</td><td class="num">${s.bytes}</td></tr>`).join("") + "</tbody></table>"
                    : '<p class="meta">Aucun paquet reçu. Vérifiez l\'interface choisie : sur un serveur à plusieurs pattes, « par défaut » est celle de la route par défaut, rarement le fabric.</p>') +
                (r.bridged ? '<p class="nt-warn">Mesure prise depuis un conteneur ponté : le multicast du LAN n\'y parvient pas, l\'absence de paquets ne prouve rien.</p>' : "");
        },
        scan(r) {
            return `<div class="nt-stats">${stat("Plage", r.cidr)}${stat("Vivants", r.alive + " / " + r.scanned)}${stat("Durée", r.seconds + " s")}` +
                `${r.ports_tested.length ? stat("Ports testés", r.ports_tested.join(" ")) : ""}</div>` +
                (r.hosts.length ? '<table class="nt-table"><thead><tr><th>Adresse</th><th>Nom</th><th>Ping</th><th>Ports ouverts</th></tr></thead><tbody>' +
                    r.hosts.map(x => `<tr><td class="num">${esc(x.ip)}</td><td>${esc(x.hostname || "")}</td><td class="num">${x.ms == null ? '<span class="nt-muted">muet</span>' : esc(ms(x.ms))}</td>` +
                        `<td class="num">${esc(x.ports.join(" "))}</td></tr>`).join("") + "</tbody></table>" : '<p class="meta">Personne n\'a répondu.</p>');
        },
    };

    // ── Surveillance ────────────────────────────────────────────
    function formMonitor(m) {
        monEdit = m || null;
        const k = (m && m.kind) || (MON_KINDS.includes(kind) ? kind : "ping");
        const box = $("#nt-monform");
        box.innerHTML = `<h3>${m && m.id ? "Modifier le contrôle" : "Nouveau contrôle"}</h3><div class="nt-fields">` +
            champHtml({ k: "name", l: "Nom", t: "text", ph: "ex. Contrôleur — Ember+", wide: true }, m ? m.name : "", "nt-m-", true) +
            champHtml({ k: "kind", l: "Test", t: "select", opts: MON_KINDS.map(x => [x, KINDS[x].label]) }, k, "nt-m-", true) +
            champHtml({ k: "interval_s", l: "Toutes les (s)", t: "number", min: (INFO && INFO.limits.interval_min_s) || 10 }, m ? m.interval_s : 60, "nt-m-", true) +
            champHtml({ k: "fail_threshold", l: "Alerter après N échecs", t: "number", min: 1, max: 20 }, m ? m.fail_threshold : 3, "nt-m-", true) +
            champHtml({ k: "mail", l: "Prévenir par e-mail", t: "check" }, m ? m.mail : false, "nt-m-", true) +
            champHtml({ k: "mail_to", l: "Destinataires", t: "text", ph: "défaut : ceux du service mail" }, m ? m.mail_to : "", "nt-m-", true) +
            '<div class="nt-sep"></div><div class="nt-fields is-params" style="grid-column:1/-1"></div></div>' +
            '<div class="nt-actions"><button class="btn btn-blue" type="button" data-act="mon-save">Enregistrer</button>' +
            '<button class="btn" type="button" data-act="mon-cancel">Annuler</button></div>';
        const dessinerParams = (kk, vals) => {
            box.querySelector(".is-params").innerHTML = KINDS[kk].fields.map(f => champHtml(f, vals ? vals[f.k] : undefined, "nt-mp-", true)).join("");
        };
        dessinerParams(k, m ? m.params : null);
        box.querySelector('[data-k="kind"]').addEventListener("change", (e) => dessinerParams(e.target.value, null));
        box.hidden = false;
        box.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }

    async function sauverMonitor() {
        const box = $("#nt-monform");
        const val = (k) => box.querySelector(`[data-k="${k}"]`);
        const k = val("kind").value;
        const corps = {
            name: val("name").value.trim(), kind: k,
            interval_s: Number(val("interval_s").value), fail_threshold: Number(val("fail_threshold").value),
            mail: val("mail").checked, mail_to: val("mail_to").value.trim(),
            params: lireChamps(box.querySelector(".is-params"), k),
        };
        if (!corps.name) { toast("Donnez un nom au contrôle.", "error"); return; }
        try {
            if (monEdit && monEdit.id) await CTX.api("monitors/" + monEdit.id, { method: "PUT", body: corps });
            else await CTX.api("monitors", { body: corps });
            box.hidden = true; monEdit = null;
            toast("Contrôle enregistré.", "success");
            await chargerMonitors();
        } catch (e) { if (!e.rightsShown) toast(e.message, "error"); }
    }

    let MONS = [];
    async function chargerMonitors() {
        let r;
        try { r = await CTX.api("monitors"); } catch (e) { return; }
        MONS = r.monitors || [];
        const down = MONS.filter(m => m.enabled && m.state.status === "down").length;
        const pill = $("#nt-mon-count");
        pill.hidden = !down; pill.textContent = down;
        $("#nt-mon-empty").hidden = MONS.length > 0;
        $("#nt-mon-table").hidden = MONS.length === 0;
        const gerer = peut("monitor.manage");
        $("#nt-mon-new").hidden = !gerer;
        $("#nt-mon-table tbody").innerHTML = MONS.map(m => {
            const st = m.enabled ? m.state.status : "paused";
            const libSt = { up: "en succès", down: "EN ÉCHEC", unknown: "pas encore de verdict", paused: "suspendu" }[st] || st;
            const strip = (m.points || []).slice(-60).map(p => `<i class="${p.ok ? "" : "is-ko"}" title="${esc(quand(p.t))}${p.ms != null ? " · " + esc(ms(p.ms)) : ""}"></i>`).join("");
            const echecs = m.state.failures ? ` <span class="nt-muted">(${m.state.failures} échec${m.state.failures > 1 ? "s" : ""} de suite)</span>` : "";
            return `<tr data-id="${m.id}"><td><span class="nt-dot is-${st}" title="${esc(libSt)}"></span></td>` +
                `<td><b>${esc(m.name)}</b>${m.mail ? ' <span class="nt-muted" title="Alerte par e-mail">✉</span>' : ""}</td>` +
                `<td>${esc(KINDS[m.kind] ? KINDS[m.kind].label : m.kind)} <span class="nt-mono">${esc(m.label)}</span></td>` +
                `<td>${esc(intervalle(m.interval_s))}</td>` +
                `<td class="${st === "down" ? "nt-ko" : ""}">${esc(m.state.last_summary || "—")}${echecs}<br><span class="nt-muted">${esc(quand(m.state.last_run))}</span></td>` +
                `<td>${m.state.since ? esc(duree(m.state.since)) : "—"}</td>` +
                `<td><div class="nt-strip">${strip}</div></td>` +
                `<td><div class="nt-rowact"><button class="btn btn-sm" data-act="mon-run" title="Exécuter maintenant">▶</button>` +
                (gerer ? `<button class="btn btn-sm" data-act="mon-toggle">${m.enabled ? "Suspendre" : "Reprendre"}</button>` +
                    `<button class="btn btn-sm" data-act="mon-edit">Modifier</button>` +
                    `<button class="btn btn-sm btn-red" data-act="mon-del" title="Supprimer">✕</button>` : "") +
                "</div></td></tr>";
        }).join("");
    }

    async function actionMonitor(act, id) {
        const m = MONS.find(x => String(x.id) === String(id));
        if (!m) return;
        try {
            if (act === "mon-run") { await CTX.api("monitors/" + id + "/run", { body: {} }); }
            else if (act === "mon-toggle") { await CTX.api("monitors/" + id, { method: "PUT", body: { enabled: !m.enabled } }); }
            else if (act === "mon-edit") { formMonitor(m); return; }
            else if (act === "mon-del") {
                if (!confirm("Supprimer le contrôle « " + m.name + " » et son historique ?")) return;
                await CTX.api("monitors/" + id, { method: "DELETE" });
            }
            await chargerMonitors();
        } catch (e) { if (!e.rightsShown) toast(e.message, "error"); }
    }

    // ── Historique ──────────────────────────────────────────────
    let HIST = [];
    async function chargerHistorique() {
        const k = $("#nt-h-kind").value;
        let r;
        try { r = await CTX.api("history" + (k ? "?kind=" + encodeURIComponent(k) : "")); } catch (e) { return; }
        HIST = r.history || [];
        $("#nt-h-empty").hidden = HIST.length > 0;
        $("#nt-h-table").hidden = HIST.length === 0;
        $("#nt-h-clear").hidden = !peut("history.clear") || HIST.length === 0;
        $("#nt-h-table tbody").innerHTML = HIST.map(h =>
            `<tr class="is-click" data-hid="${h.id}"><td><span class="nt-dot is-${h.ok ? "up" : "down"}"></span></td>` +
            `<td>${esc(quand(h.at))}</td><td>${esc(KINDS[h.kind] ? KINDS[h.kind].label : h.kind)}</td>` +
            `<td class="nt-mono">${esc(h.label)}</td><td class="${h.ok ? "" : "nt-ko"}">${esc(h.summary || "")}</td>` +
            `<td class="nt-muted">${esc(h.user || "")}</td></tr>` +
            (ouverts.has(h.id) ? `<tr class="nt-detail-row" data-detail="${h.id}"><td colspan="6">Chargement…</td></tr>` : "")).join("");
        ouverts.forEach(id => remplirDetail(id));
    }

    async function remplirDetail(id) {
        const cell = EL.querySelector(`tr[data-detail="${id}"] > td`);
        if (!cell) return;
        try {
            const h = await CTX.api("history/" + id);
            cell.innerHTML = rendreResultat({ ...h, id }, false);
        } catch (e) { cell.textContent = e.message; }
    }

    // ── Onglets & événements ────────────────────────────────────
    function onglet(nom) {
        $$(".nt-tab").forEach(b => b.classList.toggle("is-on", b.dataset.tab === nom));
        $$("section[data-pane]").forEach(s => { s.hidden = s.dataset.pane !== nom; });
        if (nom === "surveillance") chargerMonitors();
        if (nom === "historique") chargerHistorique();
    }

    function onClick(e) {
        const tab = e.target.closest(".nt-tab");
        if (tab) { onglet(tab.dataset.tab); return; }
        const kb = e.target.closest(".nt-kind");
        if (kb && !kb.disabled) {
            kind = kb.dataset.kind;
            $$(".nt-kind").forEach(b => b.classList.toggle("is-on", b === kb));
            dessinerForm();
            return;
        }
        const act = e.target.closest("[data-act]");
        if (act) {
            const a = act.dataset.act;
            if (a === "watch" && dernier) {
                onglet("surveillance");
                formMonitor({ kind: dernier.kind, params: dernier.params, name: "", interval_s: 60, fail_threshold: 3, mail: false, mail_to: "" });
                return;
            }
            if (a === "mon-save") { sauverMonitor(); return; }
            if (a === "mon-cancel") { $("#nt-monform").hidden = true; monEdit = null; return; }
            const tr = act.closest("tr[data-id]");
            if (tr) { actionMonitor(a, tr.dataset.id); return; }
        }
        const hr = e.target.closest("tr[data-hid]");
        if (hr) {
            const id = Number(hr.dataset.hid);
            if (ouverts.has(id)) ouverts.delete(id); else ouverts.add(id);
            chargerHistorique();
        }
    }

    async function mount(el, ctx) {
        EL = el; CTX = ctx;
        try { INFO = await CTX.api("info"); } catch (e) { INFO = null; }
        try {
            const r = await CTX.rights();
            ADMIN = !!r.admin; GRANTED = new Set(r.granted || []);
        } catch (e) { ADMIN = false; GRANTED = new Set(); }
        dessinerKinds();
        dessinerForm();
        $("#nt-h-kind").innerHTML = '<option value="">Tous les tests</option>' +
            Object.entries(KINDS).map(([k, d]) => `<option value="${k}">${esc(d.label)}</option>`).join("");
        EL.addEventListener("click", onClick);
        $("#nt-form").addEventListener("submit", lancer);
        $("#nt-mon-new").addEventListener("click", () => formMonitor(null));
        $("#nt-h-kind").addEventListener("change", chargerHistorique);
        $("#nt-h-clear").addEventListener("click", async () => {
            if (!confirm("Vider tout l'historique des tests ?")) return;
            try { await CTX.api("history", { method: "DELETE" }); ouverts.clear(); await chargerHistorique(); }
            catch (e) { if (!e.rightsShown) toast(e.message, "error"); }
        });
        chargerCibles();
        chargerMonitors();
        // La surveillance vit côté serveur ; l'écran se contente de la relire, et seulement
        // quand l'onglet est affiché — inutile de solliciter l'app pour une page cachée.
        timer = setInterval(() => {
            if (!EL || document.hidden) return;
            const pane = EL.querySelector('section[data-pane="surveillance"]');
            if (pane && !pane.hidden && $("#nt-monform").hidden) chargerMonitors();
        }, 5000);
    }

    function unmount() {
        if (timer) clearInterval(timer);
        timer = null;
        if (EL) EL.removeEventListener("click", onClick);
        EL = null; CTX = null;
    }

    return { mount, unmount };
})();
