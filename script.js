// --- Base64 polyfill and helper functions (from your original code) ---
// (Keep this section as it was provided in the previous version)
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


// --- Define your single DEFAULT base template here ---
// (Keep this section as it was provided in the previous version)
const defaultBaseTemplate = {
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
      {
        "clash_mode": "Direct",
        "server": "dns-direct"
      },
      {
        "clash_mode": "Global",
        "rule_set": [
          "geosite-category-games"
        ],
        "domain_suffix": [
          "xiaomi.com"
        ],
        "server": "dns-remote"
      },
      {
        "clash_mode": "Global",
        "server": "dns-fake"
      },
      {
        "query_type": [
          64,
          65
        ],
        "action": "predefined",
        "rcode": "NOTIMP"
      },
       {
         "query_type": "HTTPS",
         "action": "reject"
       },
      {
        "type": "logical",
        "mode": "and",
        "rules": [
          {
            "clash_mode": "AllowAds",
            "invert": true
          },
          {
            "rule_set": "geosite-category-ads-all"
          }
        ],
        "action": "predefined",
        "rcode": "NOERROR",
        "answer": "A"
      },
      {
        "type": "logical",
        "mode": "and",
        "rules": [
          {
            "query_type": [
              "A",
              "AAAA"
            ]
          },
          {
            "rule_set": [
              "geosite-category-games"
            ],
            "domain_suffix": [
              "xiaomi.com"
            ],
            "invert": true
          }
        ],
        "action": "route",
        "server": "dns-fake",
        "rewrite_ttl": 1
      },
      {
        "domain_suffix": [
          "bing.com",
          "googleapis.cn",
          "gstatic.com"
        ],
        "server": "dns-remote"
      },
      {
        "domain_suffix": [
          "senhewenhua.com",
          "cnmdm.top",
          "akamaized.net",
          "moedot.net",
          "cycani.org",
          "skland.com",
          "aliyun.com",
          "online-fix.me"
        ],
        "rule_set": [
          "geosite-cn"
        ],
        "server": "dns-direct"
      }
    ],
    "final": "dns-remote",
    "independent_cache": true
  },
  "inbounds": [
    {
      "endpoint_independent_nat": false,
      "auto_route": true,
      "address": [
        "172.19.0.1/28",
        "fdfe:dcba:9876::1/126"
      ],
      "platform": {
        "http_proxy": {
          "enabled": true,
          "server": "127.0.0.1",
          "server_port": 20808
        }
      },
      "mtu": 9000,
      "stack": "mixed",
      "tag": "tun-in",
      "type": "tun"
    },
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": 20808
    },
    {
      "type": "mixed",
      "tag": "mixed-in2",
      "listen": "127.0.0.1",
      "listen_port": 20809
    }
  ],
  "outbounds": [
     {
        "tag": "proxy",
        "type": "selector",
        "outbounds": []
     },
      {
         "tag": "Auto",
         "type": "urltest",
         "outbounds": [],
         "url": "http://cp.cloudflare.com/generate_204",
         "interval": "10m"
     },
     {
        "tag": "direct",
        "type": "direct"
     },
     {
         "tag": "bypass",
         "type": "direct"
     },
     {
        "tag": "block",
        "type": "block"
     },
     {
         "tag": "reject",
         "type": "reject"
     }
  ],
  "route": {
    "default_domain_resolver": {
      "server": "dns-direct"
    },
    "rules": [
      {
        "inbound": [
          "mixed-in2"
        ],
        "outbound": "proxy"
      },
      {
        "rule_set": "geoip-telegram",
        "clash_mode": "Direct",
        "outbound": "direct"
      },
      {
        "rule_set": "geoip-telegram",
        "outbound": "proxy"
      },
      {
        "action": "sniff",
        "sniffer": [
          "http",
          "tls",
          "quic",
          "dns"
        ],
        "timeout": "500ms"
      },
      {
        "type": "logical",
        "mode": "or",
        "rules": [
          {
            "port": 53
          },
          {
            "protocol": "dns"
          }
        ],
        "action": "hijack-dns"
      },
      {
        "ip_is_private": true,
        "outbound": "direct"
      },
      {
        "rule_set": "geosite-private",
        "outbound": "direct"
      },
      {
        "outbound": "proxy",
        "clash_mode": "Global"
      },
      {
        "outbound": "direct",
        "clash_mode": "Direct"
      },
       {
           "clash_mode": "AllowAds",
           "outbound": "direct"
       },
      {
        "type": "logical",
        "mode": "or",
        "rules": [
          {
            "protocol": "quic"
          },
          {
            "network": "udp",
            "port": 443
          }
        ],
        "action": "reject",
        "method": "default"
      },
      {
        "source_ip_cidr": [
          "224.0.0.0/3",
          "ff00::/8"
        ],
        "ip_cidr": [
          "224.0.0.0/3",
          "ff00::/8"
        ],
        "action": "reject",
        "method": "default"
      },
      {
        "type": "logical",
        "mode": "and",
        "rules": [
          {
            "clash_mode": "AllowAds",
            "invert": true
          },
          {
            "rule_set": "geosite-category-ads-all"
          }
        ],
        "action": "reject",
        "method": "default"
      },
      {
        "domain_suffix": [
          "bing.com",
          "googleapis.cn",
          "gstatic.com"
        ],
        "outbound": "proxy"
      },
      {
        "domain_suffix": [
          "cycani.org",
          "senhewenhua.com",
          "cnmdm.top",
          "akamaized.net",
          "moedot.net",
          "skland.com",
          "aliyun.com",
          "online-fix.me"
        ],
        "rule_set": "geosite-cn",
        "outbound": "direct"
      },
      {
        "rule_set": "geosite-geolocation-!cn",
        "outbound": "proxy"
      },
      {
        "action": "resolve",
        "server": "dns-remote"
      },
      {
        "ip_is_private": true,
        "outbound": "direct"
      },
      {
        "rule_set": "geoip-cn",
        "outbound": "direct"
      }
    ],
    "rule_set": [
      {
        "type": "remote",
        "tag": "geosite-category-ads-all",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-ads-all.srs",
        "download_detour": "proxy",
        "update_interval": "72h0m0s"
      },
      {
        "type": "remote",
        "tag": "geosite-private",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-private.srs",
        "download_detour": "proxy",
        "update_interval": "72h0m0s"
      },
      {
        "type": "remote",
        "tag": "geosite-cn",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-cn.srs",
        "download_detour": "proxy",
        "update_interval": "72h0m0s"
      },
      {
        "type": "remote",
        "tag": "geoip-cn",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geoip/geoip-cn.srs",
        "download_detour": "proxy",
        "update_interval": "72h0m0s"
      },
      {
        "type": "remote",
        "tag": "geoip-telegram",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geoip/geoip-telegram.srs",
        "download_detour": "proxy",
        "update_interval": "72h0m0s"
      },
      {
        "type": "remote",
        "tag": "geosite-geolocation-!cn",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-geolocation-!cn.srs",
        "download_detour": "proxy",
        "update_interval": "72h0m0s"
      },
      {
        "type": "remote",
        "tag": "geosite-category-games",
        "format": "binary",
        "url": "https://raw.githubusercontent.com/lyc8503/sing-box-rules/rule-set-geosite/geosite-category-games.srs",
        "download_detour": "proxy",
        "update_interval": "72h0m0s"
      }
    ],
    "final": "proxy",
    "auto_detect_interface": true
  },
  "experimental": {
    "cache_file": {
      "enabled": true,
      "path": "cache.db",
      "store_fakeip": true
    },
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "external_ui": "ui",
      "external_ui_download_url": "https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip",
      "external_ui_download_detour": "proxy"
    }
  }
};


// --- Parsing Functions (same as previous version) ---
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

// Simple SnackBar function (replace if you have a library)
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

     snackbarContainer.innerHTML = '';
     snackbarContainer.appendChild(msgElement);

     msgElement.classList.add('show');

     setTimeout(function(){
         msgElement.classList.remove('show');
         setTimeout(() => { msgElement.remove(); }, 500);
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


// --- Populate Rule Sets Section ---
function populateRuleSetsSettings(ruleSets, containerId = 'rule-sets-container') {
    const container = document.getElementById(containerId);
    if (!container) {
        console.error(`Rule sets container with ID ${containerId} not found.`);
        return;
    }
    container.innerHTML = ''; // Clear previous content

    if (!ruleSets || !Array.isArray(ruleSets)) {
        console.warn("No rule sets array found in template.");
        return;
    }

    ruleSets.forEach(ruleSet => {
        // Only display remote rule sets for editing
        if (ruleSet.type !== 'remote' || !ruleSet.tag) {
             console.warn("Skipping non-remote or untagged rule set:", ruleSet);
            return;
        }

        const tag = ruleSet.tag.replace(/[^a-zA-Z0-9_-]/g, ''); // Sanitize tag for ID

        const ruleSetHtml = `
            <div class="rule-set-item">
                <h4>${ruleSet.tag}</h4>
                <div class="setting-item setting-checkbox">
                    <input type="checkbox" id="ruleset-${tag}-enabled" ${true ? 'checked' : ''}>
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
        container.insertAdjacentHTML('beforeend', ruleSetHtml);
    });
}


// --- Populate Settings Form with values from a Config Object ---
function populateSettingsForm(config) {
    console.log("Populating settings form from config:", config);
    try { document.getElementById('log-level').value = config.log?.level || 'error'; } catch(e){ console.warn("Failed to set log level", e); }
    try { document.getElementById('log-timestamp').checked = config.log?.timestamp === true; } catch(e){ console.warn("Failed to set log timestamp", e); }

    try {
        const mixedIn = config.inbounds?.find(i => i.tag === 'mixed-in');
        if (mixedIn) {
            document.getElementById('mixed-in-listen').value = mixedIn.listen || '127.0.0.1';
            document.getElementById('mixed-in-port').value = mixedIn.listen_port || 20808;
        } else { console.warn("Mixed-in inbound not found in template"); }
    } catch(e){ console.warn("Failed to populate mixed-in settings", e); }

     try {
        const mixedIn2 = config.inbounds?.find(i => i.tag === 'mixed-in2');
        if (mixedIn2) {
            document.getElementById('mixed-in2-port').value = mixedIn2.listen_port || 20809;
        } else { console.warn("Mixed-in2 inbound not found in template"); }
    } catch(e){ console.warn("Failed to populate mixed-in2 settings", e); }

    try {
        const tunIn = config.inbounds?.find(i => i.tag === 'tun-in');
         if (tunIn) {
            document.getElementById('tun-nat-independent').checked = tunIn.endpoint_independent_nat === true;
            document.getElementById('tun-auto-route').checked = tunIn.auto_route === true;
            document.getElementById('tun-mtu').value = tunIn.mtu || 9000;
             if (tunIn.platform?.http_proxy) {
                document.getElementById('tun-http-proxy-server').value = tunIn.platform.http_proxy.server || '127.0.0.1';
                document.getElementById('tun-http-proxy-port').value = tunIn.platform.http_proxy.server_port || 20808;
             } else { console.warn("TUN http_proxy platform not found in template or disabled"); }
         } else { console.warn("TUN inbound not found in template"); }
    } catch(e){ console.warn("Failed to populate tun settings", e); }


    try {
        const dnsRemote = config.dns?.servers?.find(s => s.tag === 'dns-remote');
        if (dnsRemote) {
            document.getElementById('dns-remote-server').value = dnsRemote.server || 'cloudflare-dns.com';
        } else { console.warn("dns-remote server not found in template"); }
    } catch(e){ console.warn("Failed to populate dns-remote server", e); }

    try {
        const dnsDirect = config.dns?.servers?.find(s => s.tag === 'dns-direct');
        if (dnsDirect) {
            document.getElementById('dns-direct-server').value = dnsDirect.server || 'dns.alidns.com';
        } else { console.warn("dns-direct server not found in template"); }
    } catch(e){ console.warn("Failed to populate dns-direct server", e); }

    try { document.getElementById('dns-independent-cache').checked = config.dns?.independent_cache === true; } catch(e){ console.warn("Failed to set dns independent_cache", e); }


    try { document.getElementById('route-final-outbound').value = config.route?.final || 'proxy'; } catch(e){ console.warn("Failed to set route final outbound", e); }
    try { document.getElementById('default-domain-resolver').value = config.route?.default_domain_resolver?.server || 'dns-direct'; } catch(e){ console.warn("Failed to set default domain resolver", e); }
    try { document.getElementById('route-auto-detect-interface').checked = config.route?.auto_detect_interface === true; } catch(e){ console.warn("Failed to set route auto_detect_interface", e); }


     try {
        const experimental = config.experimental;
         if (experimental) {
             document.getElementById('cache-file-enabled').checked = experimental.cache_file?.enabled === true;
             document.getElementById('cache-file-path').value = experimental.cache_file?.path || 'cache.db';
             document.getElementById('cache-file-store-fakeip').checked = experimental.cache_file?.store_fakeip === true;

             if (experimental.clash_api) {
                document.getElementById('clash-api-controller').value = experimental.clash_api.external_controller || '127.0.0.1:9090';
                document.getElementById('clash-api-ui-url').value = experimental.clash_api.external_ui_download_url || 'https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip';
                 document.getElementById('clash-api-ui-detour').value = experimental.clash_api.external_ui_download_detour || 'proxy';
             } else { console.warn("Clash API settings not found in template"); }
         } else { console.warn("Experimental settings not found in template"); }
     } catch(e){ console.warn("Failed to populate experimental settings", e); }

     // Populate remote rule sets
     populateRuleSetsSettings(config.route?.rule_set);
}


// --- Apply Settings From Form to Template Object ---
function applySettingsToTemplate(template) {
    // Deep copy the template first
    const config = JSON.parse(JSON.stringify(template));

    try { if (config.log) config.log.level = document.getElementById('log-level').value; } catch(e){ console.warn("Failed to apply log level", e); }
    try { if (config.log) config.log.timestamp = document.getElementById('log-timestamp').checked; } catch(e){ console.warn("Failed to apply log timestamp", e); }


    try {
        const mixedIn = config.inbounds?.find(i => i.tag === 'mixed-in');
        if (mixedIn) {
            mixedIn.listen = document.getElementById('mixed-in-listen').value;
            mixedIn.listen_port = parseInt(document.getElementById('mixed-in-port').value, 10);
            if(isNaN(mixedIn.listen_port)) mixedIn.listen_port = 20808;
        }
    } catch(e){ console.warn("Failed to apply mixed-in settings", e); }

     try {
        const mixedIn2 = config.inbounds?.find(i => i.tag === 'mixed-in2');
        if (mixedIn2) {
            mixedIn2.listen = document.getElementById('mixed-in-listen').value; // Use value from mixed-in listen field
            mixedIn2.listen_port = parseInt(document.getElementById('mixed-in2-port').value, 10);
            if(isNaN(mixedIn2.listen_port)) mixedIn2.listen_port = 20809;
        }
    } catch(e){ console.warn("Failed to apply mixed-in2 settings", e); }


    try {
        const tunIn = config.inbounds?.find(i => i.tag === 'tun-in');
         if (tunIn) {
            tunIn.endpoint_independent_nat = document.getElementById('tun-nat-independent').checked;
            tunIn.auto_route = document.getElementById('tun-auto-route').checked;
            tunIn.mtu = parseInt(document.getElementById('tun-mtu').value, 10);
             if (isNaN(tunIn.mtu)) tunIn.mtu = 9000;

             if (tunIn.platform?.http_proxy) {
                tunIn.platform.http_proxy.server = document.getElementById('tun-http-proxy-server').value;
                tunIn.platform.http_proxy.server_port = parseInt(document.getElementById('tun-http-proxy-port').value, 10);
                 if(isNaN(tunIn.platform.http_proxy.server_port)) tunIn.platform.http_proxy.server_port = 20808;
             } else {
                 // Create platform.http_proxy if it didn't exist but TUN did
                 tunIn.platform = tunIn.platform || {};
                 tunIn.platform.http_proxy = {
                     enabled: true, // Assuming enabled by default if configured via form
                     server: document.getElementById('tun-http-proxy-server').value,
                     server_port: parseInt(document.getElementById('tun-http-proxy-port').value, 10)
                 };
                 if(isNaN(tunIn.platform.http_proxy.server_port)) tunIn.platform.http_proxy.server_port = 20808;
             }
         }
    } catch(e){ console.warn("Failed to apply tun settings", e); }


    try {
        const dnsRemote = config.dns?.servers?.find(s => s.tag === 'dns-remote');
        if (dnsRemote) {
            dnsRemote.server = document.getElementById('dns-remote-server').value;
        }
    } catch(e){ console.warn("Failed to apply dns-remote server", e); }

    try {
        const dnsDirect = config.dns?.servers?.find(s => s.tag === 'dns-direct');
        if (dnsDirect) {
            dnsDirect.server = document.getElementById('dns-direct-server').value;
        }
    } catch(e){ console.warn("Failed to apply dns-direct server", e); }

    try { if (config.dns) config.dns.independent_cache = document.getElementById('dns-independent-cache').checked; } catch(e){ console.warn("Failed to apply dns independent_cache", e); }


    try { if (config.route) config.route.final = document.getElementById('route-final-outbound').value; } catch(e){ console.warn("Failed to apply route final outbound", e); }
    try {
        if (config.route) {
            config.route.default_domain_resolver = config.route.default_domain_resolver || {};
            config.route.default_domain_resolver.server = document.getElementById('default-domain-resolver').value;
        }
    } catch(e){ console.warn("Failed to apply default domain resolver", e); }
    try { if (config.route) config.route.auto_detect_interface = document.getElementById('route-auto-detect-interface').checked; } catch(e){ console.warn("Failed to apply route auto_detect_interface", e); }


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

                    if (detourInput) updatedRuleSet.download_detour = detourInput.value || undefined; // Use undefined for empty string
                    if (intervalInput) updatedRuleSet.update_interval = intervalInput.value || undefined;

                    updatedRuleSets.push(updatedRuleSet);
                } else if (!enabledCheckbox) {
                     console.warn(`Checkbox for rule set ${ruleSet.tag} not found, keeping it.`);
                     updatedRuleSets.push(ruleSet); // Keep if control not found
                } else {
                     console.log(`Rule set ${ruleSet.tag} disabled by user.`);
                }
            });
            config.route.rule_set = updatedRuleSets; // Replace the original array
        }
    } catch(e){ console.warn("Failed to apply remote rule set settings", e); }


     try {
        const experimental = config.experimental;
         if (experimental) {
             experimental.cache_file = experimental.cache_file || {};
             experimental.cache_file.enabled = document.getElementById('cache-file-enabled').checked;
             experimental.cache_file.path = document.getElementById('cache-file-path').value || undefined;
             experimental.cache_file.store_fakeip = document.getElementById('cache-file-store-fakeip').checked;

             experimental.clash_api = experimental.clash_api || {};
             experimental.clash_api.external_controller = document.getElementById('clash-api-controller').value || undefined;
             experimental.clash_api.external_ui = experimental.clash_api.external_ui || 'ui'; // Keep default if not exposed
             experimental.clash_api.external_ui_download_url = document.getElementById('clash-api-ui-url').value || undefined;
             experimental.clash_api.external_ui_download_detour = document.getElementById('clash-api-ui-detour').value || undefined;
         }
     } catch(e){ console.warn("Failed to apply experimental settings", e); }


    // Find the selector where parsed proxies should be added *in the modified config*
    const mainSelectorTag = config.route?.final || 'proxy';
    const proxySelector = config.outbounds?.find(outbound => outbound.tag === mainSelectorTag && (outbound.type === 'selector' || outbound.type === 'urltest'));

    // Find the default 'Auto' urltest if it exists in the modified config
    const autoUrlTest = config.outbounds?.find(outbound => outbound.tag === 'Auto' && outbound.type === 'urltest');


    return {
        config: config,
        proxySelector: proxySelector,
        autoUrlTest: autoUrlTest
    };
}


// --- Navigation Function ---
 function showSection(sectionId) {
     document.getElementById('input-section').style.display = 'none';
     document.getElementById('settings-section').style.display = 'none';
     document.getElementById('output-section').style.display = 'none';

     document.getElementById(sectionId).style.display = 'block';

     // Actions when showing a section
     if (sectionId === 'settings-section') {
         // Populate the settings form when navigating to it
         // We use defaultBaseTemplate here to get the structure,
         // If you wanted to preserve user-edited settings while navigating back/forth,
         // you'd need to store the state of the form inputs somewhere (e.g., a global object)
         populateSettingsForm(defaultBaseTemplate);
     } else if (sectionId === 'output-section') {
          // Trigger generation when navigating to output section
          parseAndGenerateConfig(); // This function will handle errors and navigations
     } else { // Likely 'input-section'
         // Clear output when navigating away from output section
         document.getElementById('outputConfig').value = '';
         // Optional: Clear settings form when leaving it? Probably better to keep values until reset/new session.
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
         // Apply settings from the form to a copy of the default template
        const { config, proxySelector, autoUrlTest } = applySettingsToTemplate(defaultBaseTemplate); // Use defaultBaseTemplate here
        configWithSettingsApplied = config;

         // Pass the found selectors from the modified config
        configWithSettingsApplied._proxySelector = proxySelector;
        configWithSettingsApplied._autoUrlTest = autoUrlTest;

    } catch (error) {
        console.error("Failed to apply settings to template:", error);
        SnackBar({ message: `Error applying settings: ${error.message}`, status: "error" });
        showSection('settings-section'); // Go back to settings on error
        return;
    }


    try {
        let inputText = document.getElementById("input").value.trim();
         if (!inputText) {
              SnackBar({
                 message: "Input is empty. Please paste proxy URLs.",
                 status: "error"
              });
              showSection('input-section');
              return;
         }

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
                 message: "No valid URLs were successfully parsed.",
                 status: "error"
             });
             // Show output even if empty, so user gets the base config
        }

        // --- Configuration Modification Logic ---

        const generatedConfig = configWithSettingsApplied;
        const proxySelector = generatedConfig._proxySelector;
        const autoUrlTest = generatedConfig._autoUrlTest;

        // 1. Generate unique tags for the parsed outbounds
        let tagCount = {};
        const proxyTags = validOutbounds.map((item) => {
          let tag = item.tag;
          if (typeof tag !== 'string' || tag.trim() === '') {
             tag = 'Untagged';
          }
          tag = tag.replace(/[^\w\s\-\.]/g, '_').trim();
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
             // Add the tags of the new proxies to the main selector's list
             proxySelector.outbounds.push(...proxyTags);
             console.log(`Added ${proxyTags.length} proxy tags to the '${proxySelector.tag}' selector.`);
         } else {
              console.warn(`Could not find the target selector outbound with tag '${generatedConfig.route?.final}' or it doesn't have an 'outbounds' array. New proxies will be appended but may not be used by existing routing rules correctly.`);
         }

         if (autoUrlTest && autoUrlTest.outbounds && Array.isArray(autoUrlTest.outbounds)) {
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

         if (servers.length === 0) {
               if (generatedConfig.dns && generatedConfig.dns.rules) {
                   const originalRuleCount = generatedConfig.dns.rules.length;
                   generatedConfig.dns.rules = generatedConfig.dns.rules.filter((rule) => {
                       return !(
                           (rule.server === "direct-dns") ||
                           (rule.action === "hijack-dns" && rule.server === "direct-dns")
                       );
                   });

                   if (generatedConfig.dns.rules.length < originalRuleCount) {
                       console.log(`Removed direct-dns rule(s) from config because no domain servers were found in outbounds.`);
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

        // Navigation to output is handled by the onclick in HTML now

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
     // Populate the settings form with default values initially
     populateSettingsForm(defaultBaseTemplate);
     // Start on the input section
     showSection('input-section');
 });