
// --- Base64 polyfill and helper functions (same as previous version) ---
var version = "3.7.5";
var VERSION = version;
var _hasatob = typeof atob === "function";
var _hasbtoa = typeof btoa === "function";
var _hasBuffer = typeof Buffer === "function";
var _TD = typeof TextDecoder === "function" ? new TextDecoder() : void 0;
var _TE = typeof TextEncoder === "function" ? new TextEncoder() : void 0;
var b64ch = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
var b64chs = Array.prototype.slice.call(b64ch);
var b64tab = ((a) => {
  let tab = {};
  a.forEach((c, i) => tab[c] = i);
  return tab;
})(b64chs);
var b64re = /^(?:[A-Za-z\d+\/]{4})*?(?:[A-Za-z\d+\/]{2}(?:==)?|[A-Za-z\d+\/]{3}=?)?$/;
var _fromCC = String.fromCharCode.bind(String);
var _U8Afrom = typeof Uint8Array.from === "function" ? Uint8Array.from.bind(Uint8Array) : (it) => new Uint8Array(Array.prototype.slice.call(it, 0));
var _mkUriSafe = (src) => src.replace(/=/g, "").replace(/[+\/]/g, (m0) => m0 == "+" ? "-" : "_");
var _tidyB64 = (s) => s.replace(/[^A-Za-z0-9\+\/]/g, "");
var btoaPolyfill = (bin) => {
  let u32, c0, c1, c2, asc = "";
  const pad = bin.length % 3;
  for (let i = 0; i < bin.length;) {
    if ((c0 = bin.charCodeAt(i++)) > 255 || (c1 = bin.charCodeAt(i++)) > 255 || (c2 = bin.charCodeAt(i++)) > 255)
      throw new TypeError("invalid character found");
    u32 = c0 << 16 | c1 << 8 | c2;
    asc += b64chs[u32 >> 18 & 63] + b64chs[u32 >> 12 & 63] + b64chs[u32 >> 6 & 63] + b64chs[u32 & 63];
  }
  return pad ? asc.slice(0, pad - 3) + "===".substring(pad) : asc;
};
var _btoa = _hasbtoa ? (bin) => btoa(bin) : _hasBuffer ? (bin) => Buffer.from(bin, "binary").toString("base64") : btoaPolyfill;
var _fromUint8Array = _hasBuffer ? (u8a) => Buffer.from(u8a).toString("base64") : (u8a) => {
  const maxargs = 4096;
  let strs = [];
  for (let i = 0, l = u8a.length; i < l; i += maxargs) {
    strs.push(_fromCC.apply(null, u8a.subarray(i, i + maxargs)));
  }
  return _btoa(strs.join(""));
};
var fromUint8Array = (u8a, urlsafe = false) => urlsafe ? _mkUriSafe(_fromUint8Array(u8a)) : _fromUint8Array(u8a);
var cb_utob = (c) => {
  if (c.length < 2) {
    var cc = c.charCodeAt(0);
    return cc < 128 ? c : cc < 2048 ? _fromCC(192 | cc >>> 6) + _fromCC(128 | cc & 63) : _fromCC(224 | cc >>> 12 & 15) + _fromCC(128 | cc >>> 6 & 63) + _fromCC(128 | cc & 63);
  } else {
    var cc = 65536 + (c.charCodeAt(0) - 55296) * 1024 + (c.charCodeAt(1) - 56320);
    return _fromCC(240 | cc >>> 18 & 7) + _fromCC(128 | cc >>> 12 & 63) + _fromCC(128 | cc >>> 6 & 63) + _fromCC(128 | cc & 63);
  }
};
var re_utob = /[\uD800-\uDBFF][\uDC00-\uDFFFF]|[^\x00-\x7F]/g;
var utob = (u) => u.replace(re_utob, cb_utob);
var _encode = _hasBuffer ? (s) => Buffer.from(s, "utf8").toString("base64") : _TE ? (s) => _fromUint8Array(_TE.encode(s)) : (s) => _btoa(utob(s));
var encode = (src, urlsafe = false) => urlsafe ? _mkUriSafe(_encode(src)) : _encode(src);
var encodeURI = (src) => encode(src, true);
var re_btou = /[\xC0-\xDF][\x80-\xBF]|[\xE0-\xEF][\x80-\xBF]{2}|[\xF0-\xF7][\x80-\xBF]{3}/g;
var cb_btou = (cccc) => {
  switch (cccc.length) {
    case 4:
      var cp = (7 & cccc.charCodeAt(0)) << 18 | (63 & cccc.charCodeAt(1)) << 12 | (63 & cccc.charCodeAt(2)) << 6 | 63 & cccc.charCodeAt(3),
        offset = cp - 65536;
      return _fromCC((offset >>> 10) + 55296) + _fromCC((offset & 1023) + 56320);
    case 3:
      return _fromCC((15 & cccc.charCodeAt(0)) << 12 | (63 & cccc.charCodeAt(1)) << 6 | 63 & cccc.charCodeAt(2));
    default:
      return _fromCC((31 & cccc.charCodeAt(0)) << 6 | 63 & cccc.charCodeAt(1));
  }
};
var btou = (b) => b.replace(re_btou, cb_btou);
var atobPolyfill = (asc) => {
  asc = asc.replace(/\s+/g, "");
  if (!b64re.test(asc))
    throw new TypeError("malformed base64.");
  asc += "==".slice(2 - (asc.length & 3));
  let u24, bin = "",
    r1, r2;
  for (let i = 0; i < asc.length;) {
    u24 = b64tab[asc.charAt(i++)] << 18 | b64tab[asc.charAt(i++)] << 12 | (r1 = b64tab[asc.charAt(i++)]) << 6 | (r2 = b64tab[asc.charAt(i++)]);
    bin += r1 === 64 ? _fromCC(u24 >> 16 & 255) : r2 === 64 ? _fromCC(u24 >> 16 & 255, u24 >> 8 & 255) : _fromCC(u24 >> 16 & 255, u24 >> 8 & 255, u24 & 255);
  }
  return bin;
};
var _atob = _hasatob ? (asc) => atob(_tidyB64(asc)) : _hasBuffer ? (asc) => Buffer.from(asc, "base64").toString("binary") : atobPolyfill;
var _toUint8Array = _hasBuffer ? (a) => _U8Afrom(Buffer.from(a, "base64")) : (a) => _U8Afrom(_atob(a).split("").map((c) => c.charCodeAt(0)));
var toUint8Array = (a) => _toUint8Array(_unURI(a));
var _decode = _hasBuffer ? (a) => Buffer.from(a, "base64").toString("utf8") : _TD ? (a) => _TD.decode(_toUint8Array(a)) : (a) => btou(_atob(a));
var _unURI = (a) => _tidyB64(a.replace(/[-_]/g, (m0) => m0 == "-" ? "+" : "/"));
var decode = (src) => _decode(_unURI(src));
var isValid = (src) => {
  if (typeof src !== "string")
    return false;
  const s = src.replace(/\s+/g, "").replace(/={0,2}$/, "");
  return !/[^\s0-9a-zA-Z\+\/]/g.test(s) || !/[^\s0-9a-zA-Z\-_]/g.test(s);
};
var _noEnum = (v) => {
  return {
    value: v,
    enumerable: false,
    writable: true,
    configurable: true
  };
};
var gBase64 = {
  version,
  VERSION,
  atob: _atob,
  atobPolyfill,
  btoa: _btoa,
  btoaPolyfill,
  fromBase64: decode,
  toBase64: encode,
  encode,
  encodeURI,
  encodeURL: encodeURI,
  utob,
  btou,
  decode,
  isValid,
  fromUint8Array,
  toUint8Array
};
// --- End Base64 polyfill and helpers ---


// --- Define Your Base Templates ---
const templateV1_12 = {
  "log": {
    "level": "error",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "dns-remote",
        "type": "https",
        "server": "cloudflare-dns.com",
        "domain_resolver": "dns-local",
        "detour": "proxy"
      },
      {
        "tag": "dns-direct",
        "type": "https",
        "server": "dns.alidns.com",
        "domain_resolver": "dns-local"
      },
      {
        "tag": "dns-local",
        "type": "local"
      },
      {
        "tag": "dns-fake",
        "type": "fakeip",
        "inet4_range": "198.18.0.0/15",
        "inet6_range": "fc00::/18"
      }
    ],
    "rules": [
      { "clash_mode": "Direct", "server": "dns-direct" },
      { "clash_mode": "Global", "rule_set": [ "geosite-category-games" ], "domain_suffix": [ "xiaomi.com" ], "server": "dns-remote" },
      { "clash_mode": "Global", "server": "dns-fake" },
      { "query_type": [ 64, 65 ], "action": "predefined", "rcode": "NOTIMP" },
       { "query_type": "HTTPS", "action": "reject" },
      {
        "type": "logical", "mode": "and",
        "rules": [ { "clash_mode": "AllowAds", "invert": true }, { "rule_set": "geosite-category-ads-all" } ],
        "action": "predefined", "rcode": "NOERROR", "answer": "A"
      },
      {
        "type": "logical", "mode": "and",
        "rules": [ { "query_type": [ "A", "AAAA" ] }, { "rule_set": [ "geosite-category-games" ], "domain_suffix": [ "xiaomi.com" ], "invert": true } ],
        "action": "route", "server": "dns-fake", "rewrite_ttl": 1
      },
      { "domain_suffix": [ "bing.com", "googleapis.cn", "gstatic.com" ], "server": "dns-remote" },
      { "domain_suffix": [ "senhewenhua.com", "cnmdm.top", "akamaized.net", "moedot.net", "cycani.org", "skland.com", "aliyun.com", "online-fix.me" ], "rule_set": [ "geosite-cn" ], "server": "dns-direct" }
    ],
    "final": "dns-remote",
    "independent_cache": true
  },
  "inbounds": [
    {
      "endpoint_independent_nat": false, "auto_route": true,
      "address": [ "172.19.0.1/28", "fdfe:dcba:9876::1/126" ],
      "platform": { "http_proxy": { "enabled": true, "server": "127.0.0.1", "server_port": 20808 } },
      "mtu": 9000, "stack": "mixed", "tag": "tun-in", "type": "tun"
    },
    { "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 20808 },
    { "type": "mixed", "tag": "mixed-in2", "listen": "127.0.0.1", "listen_port": 20809 }
  ],
  "outbounds": [
     { "tag": "proxy", "type": "selector", "outbounds": [] },
      { "tag": "Auto", "type": "urltest", "outbounds": [], "url": "http://cp.cloudflare.com/generate_204", "interval": "10m" },
     { "tag": "direct", "type": "direct" },
     { "tag": "bypass", "type": "direct" },
     { "tag": "block", "type": "block" },
     { "tag": "reject", "type": "reject" }
  ],
  "route": {
    "default_domain_resolver": { "server": "dns-direct" },
    "rules": [
      { "inbound": [ "mixed-in2" ], "outbound": "proxy" },
      { "rule_set": "geoip-telegram", "clash_mode": "Direct", "outbound": "direct" },
      { "rule_set": "geoip-telegram", "outbound": "proxy" },
      { "action": "sniff", "sniffer": [ "http", "tls", "quic", "dns" ], "timeout": "500ms" },
      { "type": "logical", "mode": "or", "rules": [ { "port": 53 }, { "protocol": "dns" } ], "action": "hijack-dns" },
      { "ip_is_private": true, "outbound": "direct" },
      { "rule_set": "geosite-private", "outbound": "direct" },
      { "outbound": "proxy", "clash_mode": "Global" },
      { "outbound": "direct", "clash_mode": "Direct" },
       { "clash_mode": "AllowAds", "outbound": "direct" },
      { "type": "logical", "mode": "or", "rules": [ { "protocol": "quic" }, { "network": "udp", "port": 443 } ], "action": "reject", "method": "default" },
      { "source_ip_cidr": [ "224.0.0.0/3", "ff00::/8" ], "ip_cidr": [ "224.0.0.0/3", "ff00::/8" ], "action": "reject", "method": "default" },
      {
        "type": "logical", "mode": "and",
        "rules": [ { "clash_mode": "AllowAds", "invert": true }, { "rule_set": "geosite-category-ads-all" } ],
        "action": "reject", "method": "default"
      },
      { "domain_suffix": [ "bing.com", "googleapis.cn", "gstatic.com" ], "outbound": "proxy" },
      { "domain_suffix": [ "cycani.org", "senhewenhua.com", "cnmdm.top", "akamaized.net", "moedot.net", "skland.com", "aliyun.com", "online-fix.me" ], "rule_set": "geosite-cn", "outbound": "direct" },
      { "rule_set": "geosite-geolocation-!cn", "outbound": "proxy" },
      { "action": "resolve", "server": "dns-remote" },
      { "ip_is_private": true, "outbound": "direct" },
      { "rule_set": "geoip-cn", "outbound": "direct" }
    ],
    "rule_set": [
      { "type": "remote", "tag": "geosite-category-ads-all", "format": "binary", "url": "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-ads-all.srs", "download_detour": "proxy", "update_interval": "72h0m0s" },
      { "type": "remote", "tag": "geosite-private", "format": "binary", "url": "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-private.srs", "download_detour": "proxy", "update_interval": "72h0m0s" },
      { "type": "remote", "tag": "geosite-cn", "format": "binary", "url": "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-cn.srs", "download_detour": "proxy", "update_interval": "72h0m0s" },
      { "type": "remote", "tag": "geoip-cn", "format": "binary", "url": "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geoip/geoip-cn.srs", "download_detour": "proxy", "update_interval": "72h0m0s" },
      { "type": "remote", "tag": "geoip-telegram", "format": "binary", "url": "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geoip/geoip-telegram.srs", "download_detour": "proxy", "update_interval": "72h0m0s" },
      { "type": "remote", "tag": "geosite-geolocation-!cn", "format": "binary", "url": "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-geolocation-!cn.srs", "download_detour": "proxy", "update_interval": "72h0m0s" },
      { "type": "remote", "tag": "geosite-category-games", "format": "binary", "url": "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-games.srs", "download_detour": "proxy", "update_interval": "72h0m0s" }
    ],
    "final": "proxy",
    "auto_detect_interface": true
  },
  "experimental": {
    "cache_file": {
      "enabled": true, "path": "cache.db", "store_fakeip": true
    },
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "external_ui": "ui",
      "external_ui_download_url": "https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip",
      "external_ui_download_detour": "proxy"
    }
  }
};

const templateV1_11 = {
  "log": {
    "disabled": false,
    "level": "warn"
  },
  "dns": {
    "final": "dns-proxy",
    "strategy": "ipv4_only",
    "cache_capacity": 2048,
    "disable_cache": false,
    "disable_expire": false,
    "independent_cache": false,
    "reverse_mapping": false,
    "rules": [
      { "rule_set": "geosite-private", "action": "route", "server": "dns-local" },
      { "outbound": "any", "action": "route", "server": "dns-direct" }
    ],
    "servers": [
      { "address": "tls://9.9.9.9", "detour": "proxy", "tag": "dns-proxy" },
      { "address": "tcp://9.9.9.9", "detour": "direct", "tag": "dns-direct" },
      { "address": "local", "detour": "direct", "tag": "dns-local" }
    ]
  },
  "experimental": {
    "cache_file": {
      "enabled": true, "store_fakeip": false, "store_rdrc": true, "rdrc_timeout": "1d"
    },
    "clash_api": {
      "external_controller": "127.0.0.1:9595",
      "external_ui": "dashboard",
      "external_ui_download_detour": "proxy",
      "external_ui_download_url": "https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip"
    }
  },
  "inbounds": [
    {
      "tag": "tun-in", "type": "tun", "interface_name": "sing-box",
      "address": [ "172.18.0.1/30" ], "mtu": 9000, "stack": "gvisor",
      "auto_route": true, "strict_route": true
    },
    { "listen": "::", "listen_port": 8181, "tag": "mixed-in-8181", "type": "mixed", "udp_fragment": false }
  ],
  "outbounds": [
    {
      "tag": "proxy", "type": "selector", "interrupt_exist_connections": true,
      "outbounds": [ "trojan-ws-mux" ] // Initial outbound, will be replaced/added to
    },
    // This template includes an example outbound, which we should ideally remove before adding parsed ones,
    // or handle it as a potential default option. For simplicity, we'll ignore this hardcoded one
    // and just add the parsed ones to the selector.
    { "tag": "direct", "type": "direct", "udp_fragment": false, "tcp_fast_open": false },
     { "tag": "block", "type": "block" }, // Added block/reject for consistency
     { "tag": "reject", "type": "reject" }
  ],
  "route": {
    "final": "proxy",
    "auto_detect_interface": true,
    "rule_set": [
      { "download_detour": "proxy", "format": "binary", "tag": "geoip-private", "type": "remote", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-private.srs" },
      { "download_detour": "proxy", "format": "binary", "tag": "geosite-private", "type": "remote", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-private.srs" },
      { "download_detour": "proxy", "format": "binary", "tag": "geoip-ir", "type": "remote", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ir.srs" },
      { "download_detour": "proxy", "format": "binary", "tag": "geosite-ir", "type": "remote", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-ir.srs" }
    ],
    "rules": [
      { "action": "sniff", "timeout": "10ms" },
      { "protocol": "dns", "action": "hijack-dns" },
      { "action": "resolve", "ip_cidr": "10.10.34.32/29" }, // This seems like a specific local setup, might need clarification
      { "action": "reject", "ip_cidr": "10.10.34.32/29" }, // Rejecting the resolved range?
      { "ip_is_private": true, "action": "route", "outbound": "direct" },
      { "action": "route", "outbound": "direct", "rule_set": [ "geoip-private", "geosite-private" ] },
      { "action": "route", "outbound": "direct", "domain_suffix": [ "do-not-proxy-site.com" ] }, // Example rule
      { "action": "route", "outbound": "proxy", "domain_suffix": [ "proxy-site.com" ] }, // Example rule
      { "action": "route", "outbound": "direct", "rule_set": [ "geoip-ir", "geosite-ir" ] }
    ]
  }
};

// Map template names to objects
const templates = {
    templateV1_12: templateV1_12,
    templateV1_11: templateV1_11
};


// --- Parsing Functions (same as previous version, handles various protocols and params) ---
// (Include the v2rayToSing function and its helper parsers: parseVmessUrl, parseVlessUrl,
// parseTrojanUrl, parseShadowsocksUrl, parseShadowsocksRUrl, parseSocksUrl, parseHttpUrl)
// (Also include the ipChecker function)
async function v2rayToSing(v2rayAccount) {
  let v2rayArrayUrl = v2rayAccount.split("\n").map(line => line.trim()).filter(line => line !== "");

  let resultParse = [];

  function parseVmessUrl(url) {
    const base64Part = url.substring(8);
    try {
        let decodeResult = gBase64.decode(base64Part);
        let parsedJSON = JSON.parse(decodeResult);
        const configResult = {
          tag: parsedJSON.ps || parsedJSON.add,
          type: "vmess",
          server: parsedJSON.add,
          server_port: ~~parsedJSON.port,
          uuid: parsedJSON.id,
          security: parsedJSON.s || "auto",
          alter_id: ~~parsedJSON.aid,
          global_padding: parsedJSON.gp === "1",
          authenticated_length: parsedJSON.al === "1",
          multiplex: {
            enabled: parsedJSON.mux?.enabled !== false,
            protocol: parsedJSON.mux?.protocol || "smux",
            max_streams: ~~parsedJSON.mux?.concurrency || 32
          }
        };
        if (parsedJSON.port === "443" || parsedJSON.tls === "tls" || parsedJSON.s === "tls") {
          configResult.tls = {
            enabled: true,
            server_name: parsedJSON.sni || parsedJSON.add,
            insecure: parsedJSON.allowInsecure === "1",
            disable_sni: false
          };
           if (parsedJSON.alpn) {
                configResult.tls.alpn = parsedJSON.alpn.split(',');
           } else if (parsedJSON.net === 'ws' || parsedJSON.net === 'grpc') {
                configResult.tls.alpn = ["h2", "http/1.1"];
           } else {
                configResult.tls.alpn = ["http/1.1"];
           }
            if (parsedJSON.fp) {
                configResult.tls.utls = {
                    enabled: true,
                    fingerprint: parsedJSON.fp
                };
            }
        }

        const transportType = parsedJSON.net;
        if (transportType === "ws") {
          configResult.transport = {
            type: "ws",
            path: parsedJSON.path || "/",
            headers: {
              Host: parsedJSON.host || parsedJSON.add
            }
          };
        } else if (transportType === "grpc") {
          configResult.transport = {
            type: "grpc",
            service_name: parsedJSON.path || "",
            idle_timeout: "15s",
            ping_timeout: "15s",
            permit_without_stream: parsedJSON.mode === "gun",
          };
        } else if (transportType === "tcp") {
             configResult.transport = {
                 type: "tcp",
                 tcp_fast_open: parsedJSON.tfo === "1"
             };
             if (parsedJSON.type === "http") {
                  configResult.transport.header = {
                      type: "http",
                      request: {
                         method: "GET",
                         path: parsedJSON.path ? [parsedJSON.path] : ["/"],
                         headers: {
                             Host: [parsedJSON.host || parsedJSON.add]
                         }
                     }
                 };
             }
        } else if (transportType === "kcp") {
             configResult.transport = {
                  type: "kcp",
                  seed: parsedJSON.seed,
                  interval: "50ms",
                  uplink_capacity: 5,
                  downlink_capacity: 20,
                  buffering_multiplier: 4,
                  read_buffer_size: "1mb",
                  write_buffer_size: "1mb",
             }
             if (parsedJSON.type) {
                 configResult.transport.header = { type: parsedJSON.type };
             }
        } else if (transportType === "quic") {
             configResult.transport = {
                  type: "quic",
                  quic_version: parsedJSON.quicSecurity || "1",
                  key: parsedJSON.key,
                  header: parsedJSON.type ? { type: parsedJSON.type } : undefined
             }
        } else if (transportType === "http") {
             configResult.transport = {
                  type: "http",
                  host: parsedJSON.host ? [parsedJSON.host] : [parsedJSON.add],
                  path: parsedJSON.path || "/"
             }
        }

        return configResult;

    } catch (e) {
        console.error("Failed to parse VMESS URL:", url, e);
        return { tag: "Error Parsing VMESS", type: "error", original_url: url, error: e.message };
    }
  }


  function parseVlessUrl(url) {
    try {
        let parsedUrl = new URL(url);
        const tag = parsedUrl.hash ? decodeURIComponent(parsedUrl.hash.substring(1)) : parsedUrl.hostname;
        const configResult = {
          tag: tag,
          type: "vless",
          server: parsedUrl.hostname,
          server_port: ~~parsedUrl.port,
          uuid: parsedUrl.username,
          flow: parsedUrl.searchParams.get("flow") || "",
          packet_encoding: parsedUrl.searchParams.get("packetEncoding") || "xudp",
          multiplex: {
            enabled: parsedUrl.searchParams.get("mux") === "1",
            protocol: parsedUrl.searchParams.get("mux_protocol") || "smux",
            max_streams: ~~parsedUrl.searchParams.get("mux_concurrency") || 32
          }
        };
        const security = parsedUrl.searchParams.get("security");
        if (parsedUrl.port === "443" || security === "tls" || security === "reality" || security === "xtls") {
          configResult.tls = {
            enabled: true,
            server_name: parsedUrl.searchParams.get("sni"),
            insecure: parsedUrl.searchParams.get("allowInsecure") === "1",
            disable_sni: false,
          };
           if (parsedUrl.searchParams.has("alpn")) {
                configResult.tls.alpn = parsedUrl.searchParams.get("alpn").split(',');
           } else if (parsedUrl.searchParams.get("type") === 'ws' || parsedUrl.searchParams.get("type") === 'grpc') {
                configResult.tls.alpn = ["h2", "http/1.1"];
           } else {
                configResult.tls.alpn = ["http/1.1"];
           }
            if (parsedUrl.searchParams.has("fp")) {
                 configResult.tls.utls = {
                    enabled: true,
                    fingerprint: parsedUrl.searchParams.get("fp")
                 };
            }
             if (security === "xtls") {
                  configResult.tls.security_type = "xtls";
             }
            if (security === "reality") {
                 configResult.tls.reality = {
                     enabled: true,
                     public_key: parsedUrl.searchParams.get("pbk"),
                     short_id: parsedUrl.searchParams.get("sid"),
                     server_name: parsedUrl.searchParams.get("sni")
                 };
                  if (!configResult.tls.server_name && configResult.tls.reality.server_name) {
                     configResult.tls.server_name = configResult.tls.reality.server_name;
                  }
            } else if (!configResult.tls.server_name) {
                 configResult.tls.server_name = parsedUrl.hostname;
            }
        }

        const transportType = parsedUrl.searchParams.get("type");
        const transportTypes = {
          ws: {
            type: "ws",
            path: parsedUrl.searchParams.get("path") || "/",
            headers: {
              Host: parsedUrl.searchParams.get("host") || parsedUrl.hostname
            }
          },
          grpc: {
            type: "grpc",
            service_name: parsedUrl.searchParams.get("serviceName") || parsedUrl.searchParams.get("path") || "",
            idle_timeout: "15s",
            ping_timeout: "15s",
            permit_without_stream: parsedUrl.searchParams.get("mode") === "gun"
          },
           http: {
               type: "http",
               host: parsedUrl.searchParams.has("host") ? parsedUrl.searchParams.get("host").split(',') : [parsedUrl.hostname],
               path: parsedUrl.searchParams.get("path") || "/"
           },
            tcp: {
               type: "tcp",
               tcp_fast_open: parsedUrl.searchParams.get("tfo") === "1",
               header: parsedUrl.searchParams.has("headerType") ? {
                   type: parsedUrl.searchParams.get("headerType"),
                   request: parsedUrl.searchParams.get("headerType") === "http" ? {
                       method: "GET",
                       path: parsedUrl.searchParams.has("path") ? [parsedUrl.searchParams.get("path")] : ["/"],
                       headers: {
                           Host: parsedUrl.searchParams.has("host") ? [parsedUrl.searchParams.get("host")] : [parsedUrl.hostname]
                       }
                   } : undefined
               } : undefined
           },
            quic: {
                type: "quic",
                quic_version: parsedUrl.searchParams.get("quicVersion") || "1",
                key: parsedUrl.searchParams.get("key"),
                header: parsedUrl.searchParams.has("headerType") ? { type: parsedUrl.searchParams.get("headerType") } : undefined
            },
             kcp: {
                type: "kcp",
                seed: parsedUrl.searchParams.get("seed"),
                interval: "50ms",
                uplink_capacity: 5,
                downlink_capacity: 20,
                buffering_multiplier: 4,
                read_buffer_size: "1mb",
                write_buffer_size: "1mb",
                 header: parsedUrl.searchParams.has("headerType") ? { type: parsedUrl.searchParams.get("headerType") } : undefined
             }

        };

        if (transportType && transportTypes[transportType]) {
            configResult.transport = transportTypes[transportType];
        } else if (transportType) {
             console.warn(`Unsupported VLESS transport type: ${transportType} in URL: ${url}`);
             configResult.transport = { type: "unsupported", original_type: transportType };
        } else {
             configResult.transport = { type: "tcp" };
             if (parsedUrl.searchParams.get("tfo") === "1") {
                configResult.transport.tcp_fast_open = true;
             }
              if (parsedUrl.searchParams.get("headerType") === "http") {
                  configResult.transport.header = {
                      type: "http",
                      request: {
                         method: "GET",
                         path: parsedUrl.searchParams.has("path") ? [parsedUrl.searchParams.get("path")] : ["/"],
                         headers: {
                             Host: parsedUrl.searchParams.has("host") ? [parsedUrl.searchParams.get("host")] : [parsedUrl.hostname]
                         }
                     }
                 };
             }
        }
        return configResult;

    } catch (e) {
         console.error("Failed to parse VLESS URL:", url, e);
         return { tag: "Error Parsing VLESS", type: "error", original_url: url, error: e.message };
    }
  }

  function parseTrojanUrl(url) {
    try {
        let parsedUrl = new URL(url);
        const tag = parsedUrl.hash ? decodeURIComponent(parsedUrl.hash.substring(1)) : parsedUrl.hostname;
        const configResult = {
          tag: tag,
          type: "trojan",
          server: parsedUrl.hostname,
          server_port: ~~parsedUrl.port,
          password: parsedUrl.username,
          multiplex: {
            enabled: parsedUrl.searchParams.get("mux") === "1",
            protocol: parsedUrl.searchParams.get("mux_protocol") || "smux",
            max_streams: ~~parsedUrl.searchParams.get("mux_concurrency") || 8
          }
        };

        const security = parsedUrl.searchParams.get("security");
        const isTls = parsedUrl.port === "443" || parsedUrl.port === "8443" || (security !== "none" && security !== "tcp" && security !== "websocket" && security !== "grpc");
        if (isTls) {
           configResult.tls = {
             enabled: true,
             server_name: parsedUrl.searchParams.get("sni"),
             insecure: parsedUrl.searchParams.get("allowInsecure") === "1",
             disable_sni: parsedUrl.searchParams.get("disable_sni") === "1",
           };

           if (parsedUrl.searchParams.has("alpn")) {
                configResult.tls.alpn = parsedUrl.searchParams.get("alpn").split(',');
           } else {
                configResult.tls.alpn = ["http/1.1"];
           }

            if (parsedUrl.searchParams.has("fp")) {
                 configResult.tls.utls = {
                    enabled: true,
                    fingerprint: parsedUrl.searchParams.get("fp")
                 };
            }
             if (security === "xtls") {
                  configResult.tls.security_type = "xtls";
             }
            if (security === "reality") {
                 configResult.tls.reality = {
                     enabled: true,
                     public_key: parsedUrl.searchParams.get("pbk"),
                     short_id: parsedUrl.searchParams.get("sid"),
                     server_name: parsedUrl.searchParams.get("sni")
                 };
                  if (!configResult.tls.server_name && configResult.tls.reality.server_name) {
                     configResult.tls.server_name = configResult.tls.reality.server_name;
                  }
            } else if (!configResult.tls.server_name) {
                 configResult.tls.server_name = parsedUrl.hostname;
            }
        }

        const transportType = parsedUrl.searchParams.get("type") || "tcp";
        const transportTypes = {
           ws: {
               type: "ws",
               path: parsedUrl.searchParams.get("path") || "/",
               headers: {
                   Host: parsedUrl.searchParams.get("host") || parsedUrl.hostname
               }
           },
           grpc: {
               type: "grpc",
               service_name: parsedUrl.searchParams.get("serviceName") || parsedUrl.searchParams.get("path") || "",
               idle_timeout: "15s",
               ping_timeout: "15s",
               permit_without_stream: parsedUrl.searchParams.get("mode") === "gun"
           },
            tcp: {
                type: "tcp",
                tcp_fast_open: parsedUrl.searchParams.get("tfo") === "1",
               header: parsedUrl.searchParams.has("headerType") ? {
                   type: parsedUrl.searchParams.get("headerType"),
                   request: parsedUrl.searchParams.get("headerType") === "http" ? {
                       method: "GET",
                       path: parsedUrl.searchParams.has("path") ? [parsedUrl.searchParams.get("path")] : ["/"],
                       headers: {
                           Host: parsedUrl.searchParams.has("host") ? [parsedUrl.searchParams.get("host")] : [parsedUrl.hostname]
                       }
                   } : undefined
               } : undefined
            }
        };

        if (transportTypes[transportType]) {
            configResult.transport = transportTypes[transportType];
        } else {
             console.warn(`Unsupported Trojan transport type: ${transportType} in URL: ${url}`);
             configResult.transport = { type: "unsupported", original_type: transportType };
        }

        return configResult;

    } catch (e) {
         console.error("Failed to parse TROJAN URL:", url, e);
         return { tag: "Error Parsing TROJAN", type: "error", original_url: url, error: e.message };
    }
  }

  function parseShadowsocksUrl(url) {
     try {
        let parsedUrl = new URL(url);
        let encoded = decodeURIComponent(parsedUrl.username);
        let decodeResult = atob(encoded);
        let shadowsocksPart = decodeResult.split(":");

        let pluginParam = parsedUrl.searchParams.get("plugin");
        let pluginPart = pluginParam ? pluginParam.split(';') : [];

        const tag = parsedUrl.hash ? decodeURIComponent(parsedUrl.hash.substring(1)) : parsedUrl.hostname;

        const configResult = {
          tag: tag,
          type: "shadowsocks",
          server: parsedUrl.hostname,
          server_port: ~~parsedUrl.port,
          method: shadowsocksPart[0],
          password: shadowsocksPart[1],
          plugin: pluginPart[0] || undefined,
          plugin_opts: pluginPart.slice(1).join(';') || undefined
        };
         if (parsedUrl.searchParams.get("security") === "tls") {
             configResult.tls = {
                 enabled: true,
                 server_name: parsedUrl.searchParams.get("sni") || parsedUrl.hostname,
                 insecure: parsedUrl.searchParams.get("allowInsecure") === "1"
             };
         }

        return configResult;

     } catch (e) {
         console.error("Failed to parse SS URL:", url, e);
         return { tag: "Error Parsing SS", type: "error", original_url: url, error: e.message };
     }
  }


   function parseShadowsocksRUrl(url) {
    let ssrUrlNoProto = url.substring(6);
    try {
        let decodeResult = gBase64.decode(ssrUrlNoProto);
        let mainParts = decodeResult.split(":");
        if (mainParts.length < 6) throw new Error("Invalid SSR format structure");

        let serverSSR = mainParts[0];
        let portSSR = mainParts[1];
        let protocolSSR = mainParts[2];
        let methodSSR = mainParts[3];
        let obfsSSR = mainParts[4];
        let remaining = mainParts.slice(5).join(":");

        let passwordAndParams = remaining.split("/?");
        let passwordBase64 = passwordAndParams[0];
        let paramsString = passwordAndParams[1] || "";

        let params = new URLSearchParams(paramsString);

        let obfs_paramBase64 = params.get("obfsparam");
        let tagBase64 = params.get("remarks");
        let proto_paramBase64 = params.get("protoparam");
        let groupBase64 = params.get("group");


        let passwordSSR, obfs_paramSSR, tagSSR, proto_paramSSR, groupSSR;
         try { passwordSSR = atob(passwordBase64); } catch (e) { console.warn("Failed to decode SSR password", passwordBase64, e); passwordSSR = passwordBase64; }
         try { obfs_paramSSR = obfs_paramBase64 ? atob(obfs_paramBase64) : undefined; } catch (e) { console.warn("Failed to decode SSR obfsparam", obfs_paramBase64, e); obfs_paramSSR = obfs_paramBase64; }
         try { tagSSR = tagBase64 ? gBase64.decode(tagBase64) : undefined; } catch (e) { console.warn("Failed to decode SSR remarks", tagBase64, e); tagSSR = tagBase64; }
         try { proto_paramSSR = proto_paramBase64 ? atob(proto_paramBase64) : undefined; } catch (e) { console.warn("Failed to decode SSR protoparam", proto_paramBase64, e); proto_paramSSR = proto_paramBase64; }
         try { groupSSR = groupBase64 ? gBase64.decode(groupBase64) : undefined; } catch (e) { console.warn("Failed to decode SSR group", groupBase64, e); groupSSR = groupBase64; }


        const configResult = {
          tag: tagSSR || serverSSR,
          type: "shadowsocksr",
          server: serverSSR,
          server_port: ~~portSSR,
          method: methodSSR,
          password: passwordSSR,
          obfs: obfsSSR,
          obfs_param: obfs_paramSSR,
          protocol: protocolSSR,
          protocol_param: proto_paramSSR,
          group: groupSSR
        };

        return configResult;

     } catch (e) {
         console.error("Failed to parse SSR URL:", url, e);
         return { tag: "Error Parsing SSR", type: "error", original_url: url, error: e.message };
     }
  }


  function parseSocksUrl(url) {
    try {
        let parsedUrl = new URL(url);
        const tag = parsedUrl.hash ? decodeURIComponent(parsedUrl.hash.substring(1)) : parsedUrl.hostname;
        const configResult = {
          tag: tag,
          type: "socks",
          server: parsedUrl.hostname,
          server_port: ~~parsedUrl.port,
          username: parsedUrl.username || undefined,
          password: parsedUrl.password || undefined,
          version: "5"
        };
        return configResult;

    } catch (e) {
         console.error("Failed to parse SOCKS URL:", url, e);
         return { tag: "Error Parsing SOCKS", type: "error", original_url: url, error: e.message };
    }
  }


  function parseHttpUrl(url) {
    try {
        let parsedUrl = new URL(url);
        const tag = parsedUrl.hash ? decodeURIComponent(parsedUrl.hash.substring(1)) : parsedUrl.hostname;

        const configResult = {
          tag: tag,
          type: "http",
          server: parsedUrl.hostname,
          server_port: ~~parsedUrl.port,
          username: parsedUrl.username || undefined,
          password: parsedUrl.password || undefined
        };

        if (parsedUrl.protocol === "https:") {
          configResult.tls = {
            enabled: true,
            insecure: parsedUrl.searchParams.get("allowInsecure") === "1",
            server_name: parsedUrl.searchParams.get("sni") || parsedUrl.hostname
          };
           if (parsedUrl.searchParams.has("alpn")) {
                configResult.tls.alpn = parsedUrl.searchParams.get("alpn").split(',');
           } else {
               configResult.tls.alpn = ["http/1.1"];
           }
            if (parsedUrl.searchParams.has("fp")) {
                 configResult.tls.utls = {
                    enabled: true,
                    fingerprint: parsedUrl.searchParams.get("fp")
                 };
            }
        }
        return configResult;

    } catch (e) {
         console.error("Failed to parse HTTP(S) URL:", url, e);
         return { tag: "Error Parsing HTTP(S)", type: "error", original_url: url, error: e.message };
    }
  }

  const protocolMap = {
    "vmess:": parseVmessUrl,
    "vless:": parseVlessUrl,
    "trojan:": parseTrojanUrl,
    "trojan-go:": parseTrojanUrl,
    "ss:": parseShadowsocksUrl,
    "ssr:": parseShadowsocksRUrl,
    "socks5:": parseSocksUrl,
    "socks:": parseSocksUrl,
    "http:": parseHttpUrl,
    "https:": parseHttpUrl
  };

  for (let i = 0; i < v2rayArrayUrl.length; i++) {
    const currentUrl = v2rayArrayUrl[i];
    try {
        let parsedUrl;
        try {
           parsedUrl = new URL(currentUrl);
        } catch (e) {
           console.error("Invalid URL format:", currentUrl, e);
           resultParse.push({ tag: "Error: Invalid URL", type: "error", original_url: currentUrl, error: e.message });
           continue;
        }

        const protocolHandler = protocolMap[parsedUrl.protocol];

        if (protocolHandler) {
           let configResult;
            try {
                 configResult = protocolHandler(currentUrl);
                 resultParse.push(configResult);
            } catch(e) {
                console.error(`Error during parsing ${parsedUrl.protocol} URL: ${currentUrl}`, e);
                 resultParse.push({ tag: `Error Parsing ${parsedUrl.protocol.toUpperCase().slice(0,-1)}`, type: "error", original_url: currentUrl, error: e.message });
            }

        } else {
          console.log("Unsupported Protocol:", parsedUrl.protocol, "for URL:", currentUrl);
           resultParse.push({ tag: "Error: Unsupported Protocol", type: "error", original_url: currentUrl, protocol: parsedUrl.protocol });
        }
     } catch (e) {
         console.error("An unexpected error occurred during URL processing:", currentUrl, e);
          resultParse.push({ tag: "Error: Unexpected Error", type: "error", original_url: currentUrl, error: e.message });
     }
  }
  return resultParse;
}

function ipChecker(str) {
    if (typeof str !== 'string' || str.trim() === '') {
        return false;
    }

    const protoIndex = str.indexOf('://');
    const hostport = protoIndex !== -1 ? str.substring(protoIndex + 3) : str;

    let host = hostport;
    if (host.startsWith('[')) {
        const endBracketIndex = host.indexOf(']');
        if (endBracketIndex !== -1) {
            host = host.substring(1, endBracketIndex);
        } else {
            return false;
        }
    } else {
        const lastColonIndex = host.lastIndexOf(':');
        if (lastColonIndex !== -1 && /^\d+$/.test(host.substring(lastColonIndex + 1))) {
             host = host.substring(0, lastColonIndex);
        }
    }

    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /^((([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:))|(([0-9a-fA-F]{1,4}:){6}(:[0-9a-fA-F]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9a-fA-F]{1,4}:){5}(((:[0-9a-fA-F]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9a-fA-F]{1,4}:){4}(((:[0-9a-fA-F]{1,4}){1,3})|((:[0-9a-fA-F]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-fA-F]{1,4}:){3}(((:[0-9a-fA-F]{1,4}){1,4})|((:[0-9a-fA-F]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-fA-F]{1,4}:){2}(((:[0-9a-fA-F]{1,4}){1,5})|((:[0-9a-fA-F]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-fA-F]{1,4}:)(((:[0-9a-fA-F]{1,4}){1,6})|((:[0-9a-fA-F]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9a-fA-F]{1,4}){1,7})|((:[0-9a-fA-F]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?$/;

    return ipv4Regex.test(host) || ipv6Regex.test(host);
}


function pasteConfig(outputId) {
  const copyText = document.getElementById(outputId);
  if (!copyText || !copyText.value) {
      SnackBar({ message: "Nothing to copy.", status: "warning" });
      return;
  }

  if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(copyText.value).then(() => {
           SnackBar({ message: "Successfully copied to clipboard.", status: "success" });
      }).catch(err => {
          console.error('Failed to copy text using Clipboard API: ', err);
           SnackBar({ message: "Failed to copy text. Please copy manually.", status: "error" });
           // Fallback
          copyText.select();
          copyText.setSelectionRange(0, 99999);
           try {
               document.execCommand('copy');
                SnackBar({ message: "Successfully copied to clipboard (fallback).", status: "success" });
           } catch (err2) {
                console.error('Fallback copy failed: ', err2);
                SnackBar({ message: "Copy failed. Please select the text and copy manually.", status: "error" });
           }
      });
  } else {
       // Fallback for older browsers
       copyText.select();
       copyText.setSelectionRange(0, 99999);
       try {
           document.execCommand('copy');
            SnackBar({ message: "Successfully copied to clipboard (fallback).", status: "success" });
       } catch (err) {
            console.error('Fallback copy failed: ', err);
            SnackBar({ message: "Copy failed. Please select the text and copy manually.", status: "error" });
       }
  }
}

function downloadConfig(outputId){
  let outputText = document.getElementById(outputId).value;

  if (!outputText) {
      SnackBar({ message: "No config generated to download.", status: "warning" });
      return;
  }

  let blob = new Blob([outputText], {type: "application/json"});
  let date = new Date();
  let dateString = date.toISOString().slice(0, 10);
  let timeString = date.toTimeString().slice(0, 8).replace(/:/g, '-');

  var url = URL.createObjectURL(blob);
  var a = document.createElement("a");
  a.href = url;
  a.download = `sing-box-config-${dateString}-${timeString}.json`;
  document.body.appendChild(a);
  a.click();

  document.body.removeChild(a);
  URL.revokeObjectURL(url);

   SnackBar({ message: `Downloaded ${a.download}`, status: "success" });
}

 function SnackBar({ message, status = "info" }) {
     console.log(`SnackBar - Status: ${status}, Message: ${message}`);
     let snackbarContainer = document.getElementById('snackbar-container');
     if (!snackbarContainer) {
         snackbarContainer = document.createElement('div');
         snackbarContainer.id = 'snackbar-container';
         document.body.appendChild(snackbarContainer);
     }

     let msgElement = document.createElement('div');
     msgElement.classList.add('snackbar', status);
     msgElement.textContent = message;

     // Clear previous messages and append the new one
     snackbarContainer.innerHTML = '';
     snackbarContainer.appendChild(msgElement);

     // Trigger the show animation
     requestAnimationFrame(() => { // Use rAF to ensure display:block is applied before transition
          msgElement.classList.add('show');
     });


     setTimeout(function(){
         // Trigger the hide animation
         msgElement.classList.remove('show');
         // Remove element after hide animation completes
         setTimeout(() => { msgElement.remove(); }, 300); // Match CSS transition duration
     }, 3000);
 }

 // --- Function to clean null/undefined properties recursively ---
function cleanObject(obj) {
    if (obj === null || typeof obj !== 'object') {
        return obj;
    }

    if (Array.isArray(obj)) {
        let cleanedArray = [];
        for (let i = 0; i < obj.length; i++) {
            const cleanedItem = cleanObject(obj[i]);
            if (cleanedItem !== null && cleanedItem !== undefined) {
                 cleanedArray.push(cleanedItem);
            }
        }
        return cleanedArray;

    } else {
        const cleanedObj = {};
        for (const key in obj) {
            if (Object.prototype.hasOwnProperty.call(obj, key)) {
                const value = obj[key];
                if (value !== null && value !== undefined) {
                     const cleanedValue = cleanObject(value);
                     if (cleanedValue !== null && cleanedValue !== undefined) {
                        cleanedObj[key] = cleanedValue;
                     }
                }
            }
        }
        return cleanedObj;
    }
}

// --- Rule Set Form Field Generation ---
function generateRuleSetHtml(ruleSet) {
    if (ruleSet.type !== 'remote' || !ruleSet.tag) {
        return ''; // Only generate HTML for remote rule sets with tags
    }
    const tag = ruleSet.tag.replace(/[^a-zA-Z0-9_-]/g, ''); // Sanitize tag for ID

    return `
        <div class="rule-set-item">
            <h4>${ruleSet.tag}</h4>
            <div class="setting-item setting-checkbox">
                <input type="checkbox" id="ruleset-${tag}-enabled" checked>
                <label for="ruleset-${tag}-enabled">Enable Rule Set</label>
                 <small>Disable to exclude this rule set.</small>
            </div>
             <div class="setting-item">
                 <label for="ruleset-${tag}-url">URL:</label>
                 <input type="text" id="ruleset-${tag}-url" value="${ruleSet.url || ''}" readonly>
                 <small>Source URL for the rule set.</small>
             </div>
            <div class="setting-item">
                <label for="ruleset-${tag}-detour">Download Detour:</label>
                <input type="text" id="ruleset-${tag}-detour" value="${ruleSet.download_detour || ''}">
                <small>Outbound tag (e.g., 'proxy', 'direct') for downloading.</small>
            </div>
            <div class="setting-item">
                <label for="ruleset-${tag}-interval">Update Interval:</label>
                <input type="text" id="ruleset-${tag}-interval" value="${ruleSet.update_interval || ''}">
                <small>e.g., "24h0m0s", "7d".</small>
            </div>
        </div>
    `;
}


// --- Populate Settings Form with values from a Config Object ---
function populateSettingsForm(config) {
    console.log("Populating settings form from config:", config);
    const settingsContainer = document.getElementById('settings-form-container');
    settingsContainer.innerHTML = ''; // Clear previous fields

    // Dynamically create form fields based on the template structure
    let html = '';

    // --- General & Logging ---
    html += '<div class="setting-group"><h3>General & Logging</h3>';
    html += `<div class="setting-item"><label for="log-level">Log Level:</label><select id="log-level">
                <option value="error">error</option><option value="warn">warn</option>
                <option value="info">info</option><option value="debug">debug</option>
                <option value="trace">trace</option></select><small>Level of detail for logs.</small></div>`;
    html += `<div class="setting-item setting-checkbox"><input type="checkbox" id="log-timestamp">
             <label for="log-timestamp">Enable Log Timestamp</label><small>Include timestamps in log entries.</small></div>`;
    html += '</div>';


    // --- Inbounds ---
    html += '<div class="setting-group"><h3>Inbounds (Listeners)</h3>';
    const mixedIn = config.inbounds?.find(i => i.tag === 'mixed-in' || i.tag === 'mixed-in-8181'); // Handle both tags
    if (mixedIn) {
        html += `<div class="setting-item"><label for="mixed-in-listen">Mixed Inbound (Socks/HTTP) Listen Address:</label>
                 <input type="text" id="mixed-in-listen" value="${mixedIn.listen || '127.0.0.1'}">
                 <small>Address for mixed-in (usually 127.0.0.1 or ::).</small></div>`; // Updated help text
        html += `<div class="setting-item"><label for="mixed-in-port">Mixed Inbound Port:</label>
                 <input type="number" id="mixed-in-port" value="${mixedIn.listen_port || 20808}" min="1" max="65535">
                 <small>Port for the main mixed-inbound (Socks/HTTP).</small></div>`;
    } else {
         console.warn("Mixed-in inbound not found in template for populating form.");
    }

    const mixedIn2 = config.inbounds?.find(i => i.tag === 'mixed-in2'); // Only in v1_12
    if (mixedIn2) {
         html += `<div class="setting-item"><label for="mixed-in2-port">Mixed Inbound 2 Port:</label>
                  <input type="number" id="mixed-in2-port" value="${mixedIn2.listen_port || 20809}" min="1" max="65535">
                  <small>Port for the second mixed-inbound (routed to proxy).</small></div>`;
    } // No warning needed if it's just not in the template

     const tunIn = config.inbounds?.find(i => i.tag === 'tun-in');
     if (tunIn) {
         html += `<div class="setting-item setting-checkbox"><input type="checkbox" id="tun-nat-independent" ${tunIn.endpoint_independent_nat === true ? 'checked' : ''}>
                  <label for="tun-nat-independent">TUN Endpoint Independent NAT</label><small>Enable/disable EIM.</small></div>`;
         html += `<div class="setting-item setting-checkbox"><input type="checkbox" id="tun-auto-route" ${tunIn.auto_route === true ? 'checked' : ''}>
                  <label for="tun-auto-route">TUN Auto Route</label><small>Let sing-box handle routing table.</small></div>`;
          // strict_route is not exposed via simple checkbox
         html += `<div class="setting-item"><label for="tun-mtu">TUN MTU:</label>
                  <input type="number" id="tun-mtu" value="${tunIn.mtu || 9000}" min="576">
                  <small>Maximum Transmission Unit for TUN.</small></div>`;

          if (tunIn.platform?.http_proxy) {
               html += `<div class="setting-item"><label for="tun-http-proxy-server">TUN HTTP Proxy Server:</label>
                        <input type="text" id="tun-http-proxy-server" value="${tunIn.platform.http_proxy.server || '127.0.0.1'}">
                        <small>Address for TUN's built-in HTTP proxy.</small></div>`;
               html += `<div class="setting-item"><label for="tun-http-proxy-port">TUN HTTP Proxy Port:</label>
                        <input type="number" id="tun-http-proxy-port" value="${tunIn.platform.http_proxy.server_port || 20808}" min="1" max="65535">
                        <small>Port for TUN's built-in HTTP proxy.</small></div>`;
          } else { console.warn("TUN http_proxy platform not found in template or disabled for populating form."); } // Added check
     } else { console.warn("TUN inbound not found in template for populating form."); } // Added check

    html += '</div>'; // End Inbounds group

    // --- DNS Settings ---
    html += '<div class="setting-group"><h3>DNS Settings</h3>';
     const dnsRemote = config.dns?.servers?.find(s => s.tag === 'dns-remote' || s.tag === 'dns-proxy'); // Handle different DNS proxy tags
     if (dnsRemote) {
        html += `<div class="setting-item"><label for="dns-remote-server">DNS Proxy Server (${dnsRemote.tag}):</label>
                 <input type="text" id="dns-remote-server" value="${dnsRemote.address || dnsRemote.server || ''}">
                 <small>Address for the main DNS server used by proxy detour (e.g., tls://9.9.9.9).</small></div>`; // Use address or server
     } else { console.warn("DNS proxy server not found in template for populating form."); }

    const dnsDirect = config.dns?.servers?.find(s => s.tag === 'dns-direct');
     if (dnsDirect) {
        html += `<div class="setting-item"><label for="dns-direct-server">DNS Direct Server:</label>
                 <input type="text" id="dns-direct-server" value="${dnsDirect.address || dnsDirect.server || ''}">
                 <small>Address for the DNS server used by direct detour (e.g., tcp://8.8.8.8).</small></div>`; // Use address or server
     } else { console.warn("DNS direct server not found in template for populating form."); }


    html += `<div class="setting-item setting-checkbox"><input type="checkbox" id="dns-independent-cache" ${config.dns?.independent_cache === true ? 'checked' : ''}>
             <label for="dns-independent-cache">Independent DNS Cache</label><small>Use a cache separate from system DNS.</small></div>`;

     // Add other DNS settings if applicable to the current template (e.g., cache_capacity, strategy)
     if (config.dns?.cache_capacity !== undefined) {
          html += `<div class="setting-item"><label for="dns-cache-capacity">DNS Cache Capacity:</label>
                   <input type="number" id="dns-cache-capacity" value="${config.dns.cache_capacity}" min="0">
                   <small>Number of entries in DNS cache.</small></div>`;
     }
      if (config.dns?.strategy !== undefined) {
           html += `<div class="setting-item"><label for="dns-strategy">DNS Strategy:</label>
                    <input type="text" id="dns-strategy" value="${config.dns.strategy || 'ipv4_only'}">
                    <small>e.g., "ipv4_only", "ipv6_only", "ipv4_first".</small></div>`;
      }
      if (config.dns?.disable_cache !== undefined) {
          html += `<div class="setting-item setting-checkbox"><input type="checkbox" id="dns-disable-cache" ${config.dns.disable_cache === true ? 'checked' : ''}>
                   <label for="dns-disable-cache">Disable DNS Cache</label><small>Turn off DNS caching.</small></div>`;
      }
      if (config.dns?.disable_expire !== undefined) {
           html += `<div class="setting-item setting-checkbox"><input type="checkbox" id="dns-disable-expire" ${config.dns.disable_expire === true ? 'checked' : ''}>
                   <label for="dns-disable-expire">Disable DNS Expire</label><small>Prevent cache expiration.</small></div>`;
      }
       if (config.dns?.reverse_mapping !== undefined) {
           html += `<div class="setting-item setting-checkbox"><input type="checkbox" id="dns-reverse-mapping" ${config.dns.reverse_mapping === true ? 'checked' : ''}>
                   <label for="dns-reverse-mapping">Enable Reverse Mapping</label><small>Perform reverse DNS lookups.</small></div>`;
      }


    html += '</div>'; // End DNS group

    // --- Routing ---
    html += '<div class="setting-group"><h3>Routing</h3>';
    html += `<div class="setting-item"><label for="route-final-outbound">Route Final Outbound Tag:</label>
             <input type="text" id="route-final-outbound" value="${config.route?.final || 'proxy'}">
             <small>The tag of the default outbound/selector for unmatched traffic (default: proxy).</small></div>`;

     if (config.route?.default_domain_resolver !== undefined) { // Only in v1_12
        html += `<div class="setting-item"><label for="default-domain-resolver">Default Domain Resolver:</label>
                 <input type="text" id="default-domain-resolver" value="${config.route?.default_domain_resolver?.server || 'dns-direct'}">
                 <small>The DNS server tag for default domain lookups (default: dns-direct).</small></div>`;
     }

    html += `<div class="setting-item setting-checkbox"><input type="checkbox" id="route-auto-detect-interface" ${config.route?.auto_detect_interface === true ? 'checked' : ''}>
             <label for="route-auto-detect-interface">Auto Detect Interface</label><small>Attempt to automatically determine the outgoing interface.</small></div>`;

    html += '</div>'; // End Routing group

    // --- Remote Rule Sets ---
     if (config.route?.rule_set && Array.isArray(config.route.rule_set)) {
         html += '<div class="setting-group"><h3>Remote Rule Sets</h3><p>Customize URL, detour, and update interval for remote rule sets.</p>';
         config.route.rule_set.forEach(ruleSet => {
             html += generateRuleSetHtml(ruleSet);
         });
         html += '</div>'; // End Rule Sets group
     } else {
         console.warn("No rule_set array found in route section of template for populating form.");
     }


    // --- Experimental & Clash API ---
    html += '<div class="setting-group"><h3>Experimental & Clash API</h3>';
     if (config.experimental?.cache_file !== undefined) { // Check if cache_file exists
         html += `<div class="setting-item setting-checkbox"><input type="checkbox" id="cache-file-enabled" ${config.experimental.cache_file?.enabled === true ? 'checked' : ''}>
                  <label for="cache-file-enabled">Enable Cache File</label><small>Store DNS/FakeIP/RDRC cache to file.</small></div>`;
         html += `<div class="setting-item"><label for="cache-file-path">Cache File Path:</label>
                  <input type="text" id="cache-file-path" value="${config.experimental.cache_file?.path || 'cache.db'}">
                  <small>Path for the cache database file.</small></div>`;
         if (config.experimental.cache_file?.store_fakeip !== undefined) {
             html += `<div class="setting-item setting-checkbox"><input type="checkbox" id="cache-file-store-fakeip" ${config.experimental.cache_file.store_fakeip === true ? 'checked' : ''}>
                      <label for="cache-file-store-fakeip">Store FakeIP in Cache</label><small>Save FakeIP mappings.</small></div>`;
         }
          if (config.experimental.cache_file?.store_rdrc !== undefined) {
              html += `<div class="setting-item setting-checkbox"><input type="checkbox" id="cache-file-store-rdrc" ${config.experimental.cache_file.store_rdrc === true ? 'checked' : ''}>
                       <label for="cache-file-store-rdrc">Store RDRC in Cache</label><small>Save RDRC entries.</small></div>`;
          }
          if (config.experimental.cache_file?.rdrc_timeout !== undefined) {
              html += `<div class="setting-item"><label for="cache-file-rdrc-timeout">RDRC Timeout:</label>
                       <input type="text" id="cache-file-rdrc-timeout" value="${config.experimental.cache_file.rdrc_timeout || '1d'}">
                       <small>Timeout for RDRC entries (e.g., "1d").</small></div>`;
          }
     } else { console.warn("Experimental cache_file settings not found in template for populating form."); }


     if (config.experimental?.clash_api !== undefined) { // Check if clash_api exists
         html += `<div class="setting-item"><label for="clash-api-controller">Clash API Controller:</label>
                  <input type="text" id="clash-api-controller" value="${config.experimental.clash_api.external_controller || '127.0.0.1:9090'}">
                  <small>Address and port for the Clash API.</small></div>`;
         if (config.experimental.clash_api.external_ui_download_url !== undefined) {
             html += `<div class="setting-item"><label for="clash-api-ui-url">Clash API UI Download URL:</label>
                      <input type="text" id="clash-api-ui-url" value="${config.experimental.clash_api.external_ui_download_url || 'https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip'}">
                      <small>URL to download external UI (e.g., dashboard ZIP).</small></div>`;
         }
          if (config.experimental.clash_api.external_ui_download_detour !== undefined) {
              html += `<div class="setting-item"><label for="clash-api-ui-detour">Clash API UI Download Detour:</label>
                       <input type="text" id="clash-api-ui-detour" value="${config.experimental.clash_api.external_ui_download_detour || 'proxy'}">
                       <small>Outbound tag for downloading the UI (default: proxy).</small></div>`;
          }
           // external_ui is typically a fixed string ("ui" or "dashboard"), not usually edited via form
     } else { console.warn("Experimental clash_api settings not found in template for populating form."); }


    html += '</div>'; // End Experimental group

    settingsContainer.innerHTML = html;

    // Set the correct log level value after HTML is inserted
    try { document.getElementById('log-level').value = config.log?.level || 'error'; } catch(e){ console.warn("Failed to set log level value post-insert", e); }

    // Attach event listener to the Reset button here
    document.getElementById('reset-settings-button').onclick = () => populateSettingsForm(getCurrentlySelectedTemplate());
}


// --- Apply Settings From Form to Template Object ---
function applySettingsToTemplate(template) {
    // Deep copy the template first
    const config = JSON.parse(JSON.stringify(template));

    // --- General & Logging ---
    try { if (config.log) config.log.level = document.getElementById('log-level').value; } catch(e){ console.warn("Failed to apply log level", e); }
    try { if (config.log) config.log.timestamp = document.getElementById('log-timestamp').checked; } catch(e){ console.warn("Failed to apply log timestamp", e); }
    // If log was missing, and enabled is false in template V1_11, keep it false if checkbox added? Not added for now.


    // --- Inbounds ---
    try {
        const mixedIn = config.inbounds?.find(i => i.tag === 'mixed-in' || i.tag === 'mixed-in-8181');
        if (mixedIn) {
            mixedIn.listen = document.getElementById('mixed-in-listen').value;
            mixedIn.listen_port = parseInt(document.getElementById('mixed-in-port').value, 10);
            if(isNaN(mixedIn.listen_port)) mixedIn.listen_port = (mixedIn.tag === 'mixed-in-8181' ? 8181 : 20808); // Fallback based on tag
        }
    } catch(e){ console.warn("Failed to apply mixed-in settings", e); }

     try {
        const mixedIn2 = config.inbounds?.find(i => i.tag === 'mixed-in2');
        if (mixedIn2) {
             mixedIn2.listen = document.getElementById('mixed-in-listen').value; // Use value from mixed-in listen field
            mixedIn2.listen_port = parseInt(document.getElementById('mixed-in2-port').value, 10);
            if(isNaN(mixedIn2.listen_port)) mixedIn2.listen_port = 20809; // Fallback
        }
    } catch(e){ console.warn("Failed to apply mixed-in2 settings", e); }


    try {
        const tunIn = config.inbounds?.find(i => i.tag === 'tun-in');
         if (tunIn) {
            if (tunIn.endpoint_independent_nat !== undefined) tunIn.endpoint_independent_nat = document.getElementById('tun-nat-independent').checked;
            if (tunIn.auto_route !== undefined) tunIn.auto_route = document.getElementById('tun-auto-route').checked;
            tunIn.mtu = parseInt(document.getElementById('tun-mtu').value, 10);
             if (isNaN(tunIn.mtu)) tunIn.mtu = 9000;

             if (tunIn.platform?.http_proxy) {
                tunIn.platform.http_proxy.server = document.getElementById('tun-http-proxy-server').value;
                tunIn.platform.http_proxy.server_port = parseInt(document.getElementById('tun-http-proxy-port').value, 10);
                 if(isNaN(tunIn.platform.http_proxy.server_port)) tunIn.platform.http_proxy.server_port = 20808;
                // Assuming platform.http_proxy.enabled is true if these fields are present
             }
             // interface_name, stack, strict_route not exposed via form
         }
    } catch(e){ console.warn("Failed to apply tun settings", e); }


    // --- DNS Settings ---
    try {
        const dnsRemote = config.dns?.servers?.find(s => s.tag === 'dns-remote' || s.tag === 'dns-proxy');
        if (dnsRemote) {
             // DNS server address can be 'address' or 'server' depending on type
             if (dnsRemote.address !== undefined) dnsRemote.address = document.getElementById('dns-remote-server').value;
             else if (dnsRemote.server !== undefined) dnsRemote.server = document.getElementById('dns-remote-server').value;
             else dnsRemote.server = document.getElementById('dns-remote-server').value; // As fallback
        }
    } catch(e){ console.warn("Failed to apply dns-remote/proxy server", e); }

    try {
        const dnsDirect = config.dns?.servers?.find(s => s.tag === 'dns-direct');
        if (dnsDirect) {
             if (dnsDirect.address !== undefined) dnsDirect.address = document.getElementById('dns-direct-server').value;
             else if (dnsDirect.server !== undefined) dnsDirect.server = document.getElementById('dns-direct-server').value;
             else dnsDirect.server = document.getElementById('dns-direct-server').value; // As fallback
        }
    } catch(e){ console.warn("Failed to apply dns-direct server", e); }

    try { if (config.dns?.independent_cache !== undefined) config.dns.independent_cache = document.getElementById('dns-independent-cache').checked; } catch(e){ console.warn("Failed to apply dns independent_cache", e); }

     // Apply other DNS settings if applicable to the current template
      try {
          if (config.dns?.cache_capacity !== undefined) {
              config.dns.cache_capacity = parseInt(document.getElementById('dns-cache-capacity').value, 10);
              if (isNaN(config.dns.cache_capacity)) config.dns.cache_capacity = 2048;
          }
      } catch(e){ console.warn("Failed to apply dns cache_capacity", e); }
      try { if (config.dns?.strategy !== undefined) config.dns.strategy = document.getElementById('dns-strategy').value; } catch(e){ console.warn("Failed to apply dns strategy", e); }
      try { if (config.dns?.disable_cache !== undefined) config.dns.disable_cache = document.getElementById('dns-disable-cache').checked; } catch(e){ console.warn("Failed to apply dns disable_cache", e); }
      try { if (config.dns?.disable_expire !== undefined) config.dns.disable_expire = document.getElementById('dns-disable-expire').checked; } catch(e){ console.warn("Failed to apply dns disable_expire", e); }
       try { if (config.dns?.reverse_mapping !== undefined) config.dns.reverse_mapping = document.getElementById('dns-reverse-mapping').checked; } catch(e){ console.warn("Failed to apply dns reverse_mapping", e); }
       // log.disabled specific to v1_11 template's log block - not exposed for simplicity, but could be added.


    // --- Routing ---
    try { if (config.route?.final !== undefined) config.route.final = document.getElementById('route-final-outbound').value; } catch(e){ console.warn("Failed to apply route final outbound", e); }
    try {
        if (config.route?.default_domain_resolver !== undefined) {
            config.route.default_domain_resolver.server = document.getElementById('default-domain-resolver').value;
        }
    } catch(e){ console.warn("Failed to apply default domain resolver", e); }
    try { if (config.route?.auto_detect_interface !== undefined) config.route.auto_detect_interface = document.getElementById('route-auto-detect-interface').checked; } catch(e){ console.warn("Failed to apply route auto_detect_interface", e); }


    // Apply Remote Rule Sets settings
    try {
        if (config.route && Array.isArray(config.route.rule_set)) {
            const originalRuleSets = config.route.rule_set;
            const updatedRuleSets = [];

            originalRuleSets.forEach(ruleSet => {
                 if (ruleSet.type !== 'remote' || !ruleSet.tag) {
                      // Keep non-remote or untagged rule sets as they are
                     updatedRuleSets.push(ruleSet);
                     return;
                 }

                const tag = ruleSet.tag.replace(/[^a-zA-Z0-9_-]/g, '');
                const enabledCheckbox = document.getElementById(`ruleset-${tag}-enabled`);
                const detourInput = document.getElementById(`ruleset-${tag}-detour`);
                const intervalInput = document.getElementById(`ruleset-${tag}-interval`);

                // Only include the rule set if the "Enable" checkbox is checked
                if (enabledCheckbox && enabledCheckbox.checked) {
                     // Create a shallow copy to modify
                    const updatedRuleSet = { ...ruleSet };

                    // Only apply if the input element exists (should due to populate logic)
                    if (detourInput) updatedRuleSet.download_detour = detourInput.value || undefined; // Use undefined for empty string
                    if (intervalInput) updatedRuleSet.update_interval = intervalInput.value || undefined; // Use undefined for empty string

                    updatedRuleSets.push(updatedRuleSet);
                } else if (!enabledCheckbox) {
                     console.warn(`Checkbox for rule set ${ruleSet.tag} not found during apply. Keeping original.`);
                     updatedRuleSets.push(ruleSet); // Keep if control not found
                } else {
                     console.log(`Rule set ${ruleSet.tag} disabled by user.`);
                }
            });
            config.route.rule_set = updatedRuleSets; // Replace the original array
        }
    } catch(e){ console.warn("Failed to apply remote rule set settings", e); }


     // --- Experimental ---
     try {
        const experimental = config.experimental;
         if (experimental) {
             // Check existence before trying to apply values
             if (experimental.cache_file !== undefined) {
                 experimental.cache_file = experimental.cache_file || {};
                 if (experimental.cache_file.enabled !== undefined) experimental.cache_file.enabled = document.getElementById('cache-file-enabled').checked;
                 if (experimental.cache_file.path !== undefined) experimental.cache_file.path = document.getElementById('cache-file-path').value || undefined;
                 if (experimental.cache_file.store_fakeip !== undefined) experimental.cache_file.store_fakeip = document.getElementById('cache-file-store-fakeip').checked;
                 if (experimental.cache_file.store_rdrc !== undefined) experimental.cache_file.store_rdrc = document.getElementById('cache-file-store-rdrc').checked;
                 if (experimental.cache_file.rdrc_timeout !== undefined) experimental.cache_file.rdrc_timeout = document.getElementById('cache-file-rdrc-timeout').value || undefined;
             }

             if (experimental.clash_api !== undefined) {
                 experimental.clash_api = experimental.clash_api || {};
                 if (experimental.clash_api.external_controller !== undefined) experimental.clash_api.external_controller = document.getElementById('clash-api-controller').value || undefined;
                 // external_ui is fixed string, not applied from form
                 if (experimental.clash_api.external_ui_download_url !== undefined) experimental.clash_api.external_ui_download_url = document.getElementById('clash-api-ui-url').value || undefined;
                 if (experimental.clash_api.external_ui_download_detour !== undefined) experimental.clash_api.external_ui_download_detour = document.getElementById('clash-api-ui-detour').value || undefined;
             }
         }
     } catch(e){ console.warn("Failed to apply experimental settings", e); }


    // Find the selector where parsed proxies should be added *in the modified config*
    // Use the potentially updated route.final tag
    const mainSelectorTag = config.route?.final || 'proxy';
    const proxySelector = config.outbounds?.find(outbound => outbound.tag === mainSelectorTag && (outbound.type === 'selector' || outbound.type === 'urltest'));

    // Find the default 'Auto' urltest if it exists in the modified config
    const autoUrlTest = config.outbounds?.find(outbound => outbound.tag === 'Auto' && outbound.type === 'urltest'); // Assuming 'Auto' tag is consistent if it exists

    return {
        config: config,
        proxySelector: proxySelector, // Return references to the specific objects for easier access later
        autoUrlTest: autoUrlTest
    };
}

// --- Get Currently Selected Template ---
function getCurrentlySelectedTemplate() {
    const selectElement = document.getElementById('template-select');
    const selectedTemplateKey = selectElement.value;
    return templates[selectedTemplateKey] ? JSON.parse(JSON.stringify(templates[selectedTemplateKey])) : JSON.parse(JSON.stringify(templateV1_12)); // Default to V1_12 if key is invalid
}


// --- Navigation Function ---
 function showSection(sectionId) {
     // Hide all sections
     document.getElementById('input-section').style.display = 'none';
     document.getElementById('settings-section').style.display = 'none';
     document.getElementById('output-section').style.display = 'none';

     // Show the requested section
     document.getElementById(sectionId).style.display = 'block';

     // Actions when showing a section
     if (sectionId === 'settings-section') {
         // Populate the settings form based on the currently selected template
         const selectedTemplate = getCurrentlySelectedTemplate();
         populateSettingsForm(selectedTemplate);
     } else if (sectionId === 'output-section') {
          // Trigger generation when navigating to output section
          parseAndGenerateConfig(); // This function handles getting settings and input
     } else { // Likely 'input-section'
         // Clear output when navigating away from output section
         document.getElementById('outputConfig').value = '';
         // Optionally, clear or reset settings form fields when leaving settings?
         // For now, we repopulate settings form on entry, so state isn't saved between visits.
     }
 }


// --- Main Generation Function ---
async function parseAndGenerateConfig() {
    // Clear previous output
    document.getElementById("outputConfig").value = "";

    let wait = SnackBar({
        message: "Please Wait. Converting...",
        status: "info"
    });

    let configWithSettingsApplied; // This will hold the template modified by settings
    try {
         // Get the currently selected template and apply settings from the form
        const selectedTemplate = getCurrentlySelectedTemplate();
        const { config, proxySelector, autoUrlTest } = applySettingsToTemplate(selectedTemplate);
        configWithSettingsApplied = config;

         // Pass the found selectors from the modified config using temporary properties
         // This is a bit hacky but avoids returning a complex structure
        configWithSettingsApplied._proxySelector = proxySelector;
        configWithSettingsApplied._autoUrlTest = autoUrlTest;

    } catch (error) {
        console.error("Failed to apply settings to template:", error);
        SnackBar({ message: `Error applying settings: ${error.message}`, status: "error" });
        showSection('settings-section'); // Go back to settings on error
        return; // Stop the process
    }


    try {
        let inputText = document.getElementById("input").value.trim();
         if (!inputText) {
              SnackBar({
                 message: "Input is empty. Please paste proxy URLs.",
                 status: "error"
              });
              showSection('input-section'); // Go back to input
              return; // Stop the process
         }

        // Attempt decoding input (same logic as previous version)
        let decodedInput = inputText;
        try {
            const potentialDecoded = decodeURIComponent(inputText);
             if (potentialDecoded !== inputText && potentialDecoded.includes('://')) {
                decodedInput = potentialDecoded;
            } else {
                 const urlParts = inputText.match(/^(https?:\/\/)(.+)$/);
                 if (urlParts && urlParts[2]) {
                      try {
                           if (b64re.test(_tidyB64(urlParts[2]))) {
                               decodedInput = gBase64.decode(urlParts[2]);
                               console.log("Decoded input as base64 subscription");
                           } else {
                               console.warn("Input looks like http/s URL but base64 part failed validation.");
                               decodedInput = inputText;
                           }
                      } catch (base64Error) {
                           console.warn("Failed to decode input as base64:", base64Error);
                           decodedInput = inputText;
                      }
                 } else {
                     decodedInput = inputText;
                 }
            }
        } catch (e) {
            console.warn("Could not decode input, using raw text:", e);
            decodedInput = inputText;
        }


        let convertAccount = await v2rayToSing(decodedInput);

        const validOutbounds = convertAccount.filter(item => item.type !== "error");
        const parsingErrors = convertAccount.filter(item => item.type === "error");

        if (parsingErrors.length > 0) {
            console.warn("Some URLs failed to parse:", parsingErrors);
            const errorMessages = parsingErrors.map(err => `Error parsing ${err.original_url || 'URL'}${err.protocol ? ' (protocol: ' + err.protocol + ')' : ''}: ${err.error || 'Unknown error'}`).join('\n');
             SnackBar({
                 message: `Warning: ${parsingErrors.length} URL(s) failed to parse. See console.`,
                 status: "warning"
             });
             console.error("--- Parsing Errors ---");
             console.error(errorMessages);
             console.error("-----------------------");
        }

        if (validOutbounds.length === 0) {
             SnackBar({
                 message: "No valid URLs were successfully parsed. Generated base config only.",
                 status: "warning"
             });
             // Continue to show the base config even if no proxies parsed
        }

        // --- Configuration Modification Logic ---

        const generatedConfig = configWithSettingsApplied;
        const proxySelector = generatedConfig._proxySelector; // Retrieve temporary references
        const autoUrlTest = generatedConfig._autoUrlTest;

        // Ensure outbounds array exists (should due to templates, but good practice)
         if (!generatedConfig.outbounds || !Array.isArray(generatedConfig.outbounds)) {
             console.error("Template is missing the 'outbounds' array.");
              SnackBar({
                 message: "Template missing 'outbounds' array. Cannot add proxies.",
                 status: "error"
              });
              // Show the output section with the base config, but indicate error
              document.getElementById("outputConfig").value = JSON.stringify(cleanObject(generatedConfig), null, 2); // Clean and show the base config
             return; // Stop adding proxies
         }


        // 1. Generate unique tags for the parsed outbounds
        let tagCount = {};
        const proxyTags = validOutbounds.map((item) => {
          let tag = item.tag;
          if (typeof tag !== 'string' || tag.trim() === '') {
             tag = 'Untagged';
          }
          tag = tag.replace(/[^\w\s\-\.]/g, '_').trim(); // Clean up invalid characters for tags
          if (tag in tagCount) {
            tagCount[tag]++;
            return `${tag}_${tagCount[tag]}`;
          } else {
            tagCount[tag] = 1;
            return tag;
          }
        });

        // Assign the generated tags back to the valid outbounds
        validOutbounds.forEach((item, index) => {
          item.tag = proxyTags[index];
        });

        // 2. Add parsed outbounds to selector groups and the main list
         if (proxySelector && proxySelector.outbounds && Array.isArray(proxySelector.outbounds)) {
              // Clear default outbounds in the selector if they exist (like "trojan-ws-mux" in v1.11)
             proxySelector.outbounds = [];
             // Add the tags of the new proxies to the main selector's list
             proxySelector.outbounds.push(...proxyTags);
             console.log(`Added ${proxyTags.length} proxy tags to the '${proxySelector.tag}' selector.`);
         } else {
              console.warn(`Could not find the target selector outbound with tag '${generatedConfig.route?.final}' or it doesn't have an 'outbounds' array. New proxies will be appended but may not be used by existing routing rules correctly.`);
         }

         if (autoUrlTest && autoUrlTest.outbounds && Array.isArray(autoUrlTest.outbounds)) {
             // Clear default outbounds in the Auto selector if they exist
             autoUrlTest.outbounds = [];
             // Add the tags to the 'Auto' selector as well
              autoUrlTest.outbounds.push(...proxyTags);
              console.log(`Added ${proxyTags.length} proxy tags to the 'Auto' urltest.`);
         } else {
              console.warn(`Could not find an 'Auto' urltest outbound or it doesn't have an 'outbounds' array. Auto selection might not work.`);
         }

         // Insert the actual valid outbound objects into the main outbounds list
         // Find the index of the main selector to insert after it, or just append
         const insertionIndex = proxySelector ? generatedConfig.outbounds.indexOf(proxySelector) + 1 : generatedConfig.outbounds.length;
         generatedConfig.outbounds.splice(insertionIndex, 0, ...validOutbounds);
         console.log(`Inserted ${validOutbounds.length} proxy configurations into the main outbounds list.`);

         // Clean up temporary references
         delete generatedConfig._proxySelector;
         delete generatedConfig._autoUrlTest;


        // 3. Modify DNS rules based on the presence of non-IP servers (using the final list of outbounds)
        const servers = generatedConfig.outbounds
                                   .map(outbound => outbound.server)
                                   .filter(server => typeof server === 'string' && server.trim() !== '')
                                   .filter(server => !ipChecker(server));

        // Logic depends on which template is active and how its DNS rules are structured
        const isV1_12 = getCurrentlySelectedTemplate() === templates.templateV1_12; // Simple check for template type

         if (generatedConfig.dns && generatedConfig.dns.rules) {
             const originalRuleCount = generatedConfig.dns.rules.length;
             if (servers.length === 0) {
                  // If NO domain servers found, remove rules pointing to 'dns-direct' or 'dns-remote' (if they rely on domain servers)
                  // This needs careful handling depending on the rule's purpose
                   generatedConfig.dns.rules = generatedConfig.dns.rules.filter((rule) => {
                       // Example: If a rule uses 'dns-direct' or 'dns-remote' AND targets domains/rulesets that rely on domain servers
                       // This is complex to determine generically. A simpler approach is to only remove rules
                       // explicitly hijacking or routing to a *specific* DNS server tag that requires a domain server backend,
                       // *if* that backend server is gone.

                       // For this example, let's focus on removing rules that resolve to a non-IP DNS server *if* no non-IP servers exist in outbounds.
                       // This is still difficult as DNS server definitions are separate.

                       // Let's stick to the previous logic: remove rules pointing to 'direct-dns' tag if no domain servers in outbounds.
                       // (Note: 'direct-dns' tag is not in your templates, but was in a prior version of your script's logic.
                       // The current templates use 'dns-direct' and 'dns-remote'/'dns-proxy' as tags).
                       // Let's check the DNS servers themselves. Are 'dns-direct' or 'dns-remote'/'dns-proxy' defined with *domain* addresses like 'cloudflare-dns.com'?
                       const dnsServers = generatedConfig.dns.servers;
                       const hasDomainDnsServer = dnsServers.some(s =>
                           (s.tag === 'dns-direct' || s.tag === 'dns-remote' || s.tag === 'dns-proxy') &&
                           typeof (s.address || s.server) === 'string' && !ipChecker(s.address || s.server)
                       );

                       // If no domain DNS servers are defined in the DNS block itself,
                       // AND no domain servers are in the outbounds, maybe remove some rules?
                       // This feels overly complex to do generically.

                       // Simpler logic: Just remove rules that *hijack* to a specific DNS server if there are no domain servers *in outbounds*.
                       // This is still not quite right. The rule's target server ('dns-direct', 'dns-remote', etc.) is defined in dns.servers.
                       // The original logic "if servers.length === 0 then filter rule.server !== 'direct-dns'" was flawed
                       // because 'direct-dns' wasn't a tag in the DNS servers list, and it wasn't checking the *type* of the DNS server backend (local, tcp, https).

                       // Let's revert to the original logic's *intent*: if there are no domain-based proxies added, does it affect DNS?
                       // In your original script, it removed the 'direct-dns' rule. This suggests that specific rule relied on a domain.
                       // In the provided templates, rules point to 'dns-direct' or 'dns-remote'/'dns-proxy'. These are defined in `dns.servers`.
                       // The `dns.servers` entries have `type` ('https', 'tcp', 'local') and `server` or `address`.
                       // The check should probably be: if the *configured* DNS server (e.g., `dns-direct`) has a *domain* address/server,
                       // and there are no *proxies with domain servers* to reach that DNS server (if it needs a detour), then maybe disable that DNS server or rule?
                       // This is getting too complex for a simple form.

                       // Let's stick to the most conservative approach: Only remove the 'direct-dns' rule if it exists (it doesn't in these templates)
                       // OR, if there are no domain *outbound servers* found among the parsed proxies, maybe disable the *remote* DNS server rule?
                       // Template V1.12: Rule `{"action": "resolve", "server": "dns-remote"}`. If no domain outbounds, maybe this rule is useless?
                       // Template V1.11: Rules point to `dns-proxy` or `dns-direct`. `dns-proxy` has `detour: "proxy"`. `dns-direct` has `detour: "direct"`.
                       // If no domain outbounds, the `dns-proxy` server might be unreachable if it's a domain.
                       // The `dns-direct` server might be unreachable if it's a domain and direct doesn't resolve domains first (it should).

                       // **Revised Simple Logic:** If *no domain-based proxy servers* are successfully parsed, warn the user that remote DNS might fail if it's domain-based, and *optionally* remove the 'resolve' rule that points to the remote DNS server, or change its server to 'dns-local'.
                       // Let's implement removing the `resolve` rule pointing to the 'dns-remote'/'dns-proxy' tag if no domain proxies were added.

                        const remoteDnsTag = generatedConfig.dns?.final || 'dns-remote'; // Get the tag of the final/remote DNS
                        const ruleTargetServer = rule.server || rule.action === 'resolve' ? rule.server : undefined; // Get the target server tag from the rule if applicable

                       // Check if the rule targets the remote/final DNS tag AND there are no domain proxies
                        if (ruleTargetServer === remoteDnsTag && servers.length === 0) {
                            console.warn(`Removing DNS rule targeting '${remoteDnsTag}' because no domain-based proxy servers were parsed.`);
                            return false; // Exclude this rule
                        }
                        // Keep other rules
                        return true;
                   });

                   if (generatedConfig.dns.rules.length < originalRuleCount) {
                       console.log(`Removed some DNS rule(s) based on lack of domain outbound servers.`);
                       SnackBar({
                           message: "Some DNS rules removed as no domain proxy servers were parsed.",
                           status: "warning"
                       });
                   }
                } else { // servers.length > 0
                    // If domain servers *are* present, ensure the 'resolve' rule targeting the remote DNS exists
                    const remoteDnsTag = generatedConfig.dns?.final || 'dns-remote';
                    const resolveRuleExists = generatedConfig.dns.rules.some(rule =>
                        rule.action === 'resolve' && rule.server === remoteDnsTag
                    );

                    if (!resolveRuleExists) {
                         // Find the index where to insert the new rule (e.g., before the final rule if it exists)
                         const finalRuleIndex = generatedConfig.dns.rules.findIndex(rule => rule === generatedConfig.dns.final); // This find is incorrect
                          // Find the index before the last rule, or just append
                         const insertionIndex = generatedConfig.dns.rules.length > 0 ? generatedConfig.dns.rules.length -1 : 0;

                         generatedConfig.dns.rules.splice(insertionIndex, 0, {
                             "action": "resolve",
                             "server": remoteDnsTag
                         });
                         console.log(`Added 'resolve' DNS rule targeting '${remoteDnsTag}' as domain servers were present.`);
                    }
                }
         }


        // 4. Clean the final object from null/undefined values
        const cleanedConfig = cleanObject(generatedConfig);

        // 5. Output the final configuration
        document.getElementById("outputConfig").value = JSON.stringify(cleanedConfig, null, 2);

        SnackBar({
          message: "Convert Success. Config generated.",
          status: "success"
        });

    } catch (error) {
        console.error("An error occurred during the conversion process:", error);
         SnackBar({
           message: `An error occurred: ${error.message}`,
           status: "error"
         });
         // Stay on output section but show error
    }
}

// --- Initial setup ---
 document.addEventListener('DOMContentLoaded', () => {
     // Add event listener for the template select dropdown
     document.getElementById('template-select').addEventListener('change', () => {
         // When template changes, repopulate the settings form with the *new* template's defaults
         const selectedTemplate = getCurrentlySelectedTemplate();
         populateSettingsForm(selectedTemplate);
         // Clear input and output when changing template? Or leave them? Leaving them might be confusing.
         // Let's clear input and output.
         document.getElementById('input').value = '';
         document.getElementById('outputConfig').value = '';
         SnackBar({ message: "Template changed. Input and Output cleared.", status: "info" });
     });

     // Populate the settings form with the *initially selected* default template on load
     const initialTemplate = getCurrentlySelectedTemplate();
     populateSettingsForm(initialTemplate);

     // Start on the input section
     showSection('input-section');
 });