// ==============================================================
// FlClash 扩展脚本（脚本模式）· 完整动态分流 v1.1
// 生成: 2026-11-16 | 适配: FlClash 脚本模式 (mihomo v1.19.33 内核)
// v1.1 (2026-11-21 三轮代码审查): 修复 geoip/geosite 同名 .mrs 缓存互覆（四对规则集 path 碰撞，
//   ipcidr 版改存 _ip 后缀与 nikki 统一）；EXCLUDE 补 剩余|重置；Prime Video 统一为 🎥；
//   DNS 监听 0.0.0.0→127.0.0.1；注释计数修正（规则集 25 / 策略组 26）
//
// 【用途】把本脚本添加到 FlClash「配置脚本」，然后:
//   配置 → 右键你的机场订阅 → 拓展 → 模式选「脚本」→ 扩展脚本选本脚本 → 立即应用
//   换机场时: 只改订阅链接, 本脚本一个字不用动, 全套规则自动套用到新节点
//
// 【机制】脚本接手订阅配置后: 保留订阅的全部节点, 重写 DNS/规则/策略组;
//   24 个规则集全部动态引用 GitHub 官方仓库(经节点拉取+24~48h自动更新);
//   微信直连等核心需求手写固定, 永不失效。
// ==============================================================

function main(config) {
  // ---------------- 基础杂项 ----------------
  config['mixed-port'] = 7890;
  config['allow-lan'] = false;
  config['external-controller'] = '127.0.0.1:9090';
  config['mode'] = 'rule';
  config['log-level'] = 'info';
  config['unified-delay'] = true;
  config['tcp-concurrent'] = true;
  config['find-process-mode'] = 'strict';
  config['global-ua'] = 'chrome';
  config['profile'] = {
    'store-selected': true,
    'store-fake-ip': true
  };
  config['geo-auto-update'] = false;
  config['geox-url'] = {
    geoip: 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat',
    geosite: 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat',
    mmdb: 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country.mmdb',
    asn: 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb'
  };

  // ---------------- DNS 防污染防泄漏 ----------------
  config['dns'] = {
    enable: true,
    listen: '127.0.0.1:1053',
    ipv6: true,
    'prefer-h3': false,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'fake-ip-filter-mode': 'blacklist',
    'fake-ip-filter': [
      'rule-set:private',
      'rule-set:cn_domain',
      'rule-set:connectivity_check',
      '+.lan',
      '+.local',
      '+.msftconnecttest.com',
      '+.msftncsi.com'
    ],
    'respect-rules': true,
    'proxy-server-nameserver': [
      'https://dns.alidns.com/dns-query',
      'https://doh.pub/dns-query'
    ],
    'direct-nameserver': [
      'https://dns.alidns.com/dns-query',
      'https://doh.pub/dns-query'
    ],
    'default-nameserver': [
      '223.5.5.5',
      '119.29.29.29'
    ],
    nameserver: [
      'https://1.1.1.1/dns-query',
      'https://8.8.8.8/dns-query'
    ],
    'nameserver-policy': {
      'rule-set:cn_domain,private': [
        'https://dns.alidns.com/dns-query',
        'https://doh.pub/dns-query'
      ]
    }
  };

  // ---------------- 域名嗅探 ----------------
  config['sniffer'] = {
    enable: true,
    'force-dns-mapping': true,
    'parse-pure-ip': true,
    sniff: {
      HTTP: { ports: [80, '8080-8880'], 'override-destination': true },
      TLS: { ports: [443, 8443] },
      QUIC: { ports: [443, 8443] }
    },
    'skip-domain': ['+.push.apple.com', 'Mijia Cloud']
  };

  // ---------------- 24 个动态规则集(全部远程引用+自动更新) ----------------
  var RAW = 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/';
  var EXCLUDE = '建议|订阅|官网|流量|到期|套餐|剩余|重置';
  function mrs(behavior, url, interval) {
    // v1.1: path 加 _ip 后缀防 geoip/geosite 同名互覆（与 nikki-skeleton 命名一致）
    return {
      type: 'http',
      behavior: behavior,
      format: 'mrs',
      url: url,
      path: './ruleset/' + url.split('/').pop().replace(/\.mrs$/, (behavior === 'ipcidr' ? '_ip' : '') + '.mrs'),
      interval: interval || 172800,
      proxy: '🚀 节点选择'
    };
  }
  config['rule-providers'] = {
    private: mrs('domain', RAW + 'geosite/private.mrs'),
    private_ip: mrs('ipcidr', RAW + 'geoip/private.mrs'),
    ads_antiad: {
      type: 'http',
      behavior: 'domain',
      format: 'yaml',
      url: 'https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-clash.yaml',
      path: './ruleset/antiad.yaml',
      interval: 86400,
      'size-limit': 0,
      proxy: '🚀 节点选择'
    },
    ads_all: mrs('domain', RAW + 'geosite/category-ads-all.mrs', 86400),
    ai_global: {
      type: 'http',
      behavior: 'classical',
      format: 'yaml',
      url: 'https://raw.githubusercontent.com/VPSDance/ai-proxy-rules/main/rules/clash/global.yaml',
      path: './ruleset/ai_global.yaml',
      interval: 86400,
      proxy: '🚀 节点选择'
    },
    telegram: mrs('domain', RAW + 'geosite/telegram.mrs'),
    telegram_ip: mrs('ipcidr', RAW + 'geoip/telegram.mrs'),
    netflix: mrs('domain', RAW + 'geosite/netflix.mrs'),
    netflix_ip: mrs('ipcidr', RAW + 'geoip/netflix.mrs'),
    primevideo: mrs('domain', RAW + 'geosite/primevideo.mrs'),
    disney: mrs('domain', RAW + 'geosite/disney.mrs'),
    youtube: mrs('domain', RAW + 'geosite/youtube.mrs'),
    spotify: mrs('domain', RAW + 'geosite/spotify.mrs'),
    bilibili: mrs('domain', RAW + 'geosite/bilibili.mrs'),
    tiktok: mrs('domain', RAW + 'geosite/tiktok.mrs'),
    twitter: mrs('domain', RAW + 'geosite/twitter.mrs'),
    github: mrs('domain', RAW + 'geosite/github.mrs'),
    microsoft: mrs('domain', RAW + 'geosite/microsoft.mrs'),
    apple: mrs('domain', RAW + 'geosite/apple.mrs'),
    google: mrs('domain', RAW + 'geosite/google.mrs'),
    game_platforms: mrs('domain', RAW + 'geosite/category-games.mrs'),
    cn_domain: mrs('domain', RAW + 'geosite/cn.mrs'),
    cn_ip: mrs('ipcidr', RAW + 'geoip/cn.mrs'),
    proxy_domain: mrs('domain', RAW + 'geosite/geolocation-!cn.mrs'),
    connectivity_check: mrs('domain', RAW + 'geosite/connectivity-check.mrs')
  };

  // ---------------- 18 个策略组(include-all 自动引用订阅全部节点) ----------------
  function areaGroup(name, filter) {
    return {
      name: name,
      type: 'url-test',
      url: 'https://www.gstatic.com/generate_204',
      interval: 300,
      tolerance: 50,
      'include-all': true,
      filter: filter,
      'exclude-filter': EXCLUDE
    };
  }
  config['proxy-groups'] = [
    {
      name: '🚀 节点选择',
      type: 'select',
      proxies: [
        '♻️ 自动选择', '🔯 香港节点', '🇯🇵 日本节点', '🇸🇬 新加坡节点',
        '🇺🇸 美国节点', '🇹🇼 台湾节点', '🇰🇷 韩国节点', '🌐 其他地区', 'DIRECT'
      ],
      'include-all': true,
      'exclude-filter': EXCLUDE
    },
    {
      name: '♻️ 自动选择',
      type: 'url-test',
      url: 'https://www.gstatic.com/generate_204',
      interval: 300,
      tolerance: 50,
      'include-all': true,
      'exclude-filter': EXCLUDE
    },
    areaGroup('🔯 香港节点', '香港|HK|Hong Kong|HongKong'),
    areaGroup('🇯🇵 日本节点', '日本|JP|Japan'),
    areaGroup('🇸🇬 新加坡节点', '新加坡|狮城|SG|Singapore'),
    areaGroup('🇺🇸 美国节点', '美国|US|United States|USA'),
    areaGroup('🇹🇼 台湾节点', '台湾|TW|Taiwan'),
    areaGroup('🇰🇷 韩国节点', '韩国|KR|Korea'),
    areaGroup('🌐 其他地区', '英国|加拿大|卢森堡|UK|Canada|Luxembourg'),
    { name: '🤖 AI服务', type: 'select', proxies: ['🇺🇸 美国节点', '🚀 节点选择', '🇯🇵 日本节点', '🇸🇬 新加坡节点', '🔯 香港节点', '🌐 其他地区', 'DIRECT'] },
    { name: '📱 Telegram', type: 'select', proxies: ['🚀 节点选择', '♻️ 自动选择', '🔯 香港节点', '🇸🇬 新加坡节点', '🇯🇵 日本节点', '🇺🇸 美国节点'] },
    { name: '📺 Netflix', type: 'select', proxies: ['🚀 节点选择', '🔯 香港节点', '🇯🇵 日本节点', '🇸🇬 新加坡节点', '🇺🇸 美国节点', '🇹🇼 台湾节点'] },
        { name: '📺 Prime Video', type: 'select', proxies: ['🚀 节点选择', '🔯 香港节点', '🇯🇵 日本节点', '🇸🇬 新加坡节点', '🇺🇸 美国节点', '🇹🇼 台湾节点'] },
    { name: '🎬 Disney+', type: 'select', proxies: ['🚀 节点选择', '🔯 香港节点', '🇯🇵 日本节点', '🇸🇬 新加坡节点', '🇺🇸 美国节点', '🇹🇼 台湾节点'] },
    { name: '▶️ YouTube', type: 'select', proxies: ['🚀 节点选择', '♻️ 自动选择', '🔯 香港节点', '🇯🇵 日本节点', '🇸🇬 新加坡节点', '🇺🇸 美国节点'] },
    { name: '🎵 Spotify', type: 'select', proxies: ['🚀 节点选择', '♻️ 自动选择', '🔯 香港节点', '🇯🇵 日本节点', '🇸🇬 新加坡节点', '🇺🇸 美国节点'] },
    { name: '🎵 TikTok', type: 'select', proxies: ['🚀 节点选择', '🇯🇵 日本节点', '🇸🇬 新加坡节点', '🇺🇸 美国节点', '🔯 香港节点', '🇹🇼 台湾节点'] },
    { name: '📺 B站', type: 'select', proxies: ['DIRECT', '🔯 香港节点', '🇹🇼 台湾节点', '🚀 节点选择'] },
    { name: '𝕏 Twitter', type: 'select', proxies: ['🚀 节点选择', '♻️ 自动选择', '🔯 香港节点', '🇯🇵 日本节点', '🇺🇸 美国节点'] },
    { name: 'Ⓜ️ 微软服务', type: 'select', proxies: ['DIRECT', '🚀 节点选择', '🔯 香港节点', '🇯🇵 日本节点'] },
    { name: '🍎 苹果服务', type: 'select', proxies: ['DIRECT', '🚀 节点选择', '🔯 香港节点'] },
    { name: '🔍 谷歌服务', type: 'select', proxies: ['🚀 节点选择', '♻️ 自动选择', '🔯 香港节点', '🇯🇵 日本节点', '🇸🇬 新加坡节点', '🇺🇸 美国节点'] },
    { name: '🎮 游戏平台', type: 'select', proxies: ['DIRECT', '🚀 节点选择'] },
    { name: '🇨🇳 国内直连', type: 'select', proxies: ['DIRECT', '🚀 节点选择'] },
    { name: '🛑 广告拦截', type: 'select', proxies: ['REJECT', 'DIRECT', '🚀 节点选择'] },
    { name: '🐟 漏网之鱼', type: 'select', proxies: ['DIRECT', '🚀 节点选择'] }
  ];

  // ---------------- 分流规则链(顺序即去重, 上方优先) ----------------
  config['rules'] = [
    // 0. 局域网/私有地址
    'RULE-SET,private,DIRECT',
    'RULE-SET,private_ip,DIRECT,no-resolve',
    // 1. 微信硬直连(核心域名手写, 不依赖远程规则, 永不失效)
    'DOMAIN-SUFFIX,qq.com,DIRECT',
    'DOMAIN-SUFFIX,wechat.com,DIRECT',
    'DOMAIN-SUFFIX,servicewechat.com,DIRECT',
    'DOMAIN-SUFFIX,wechatapp.com,DIRECT',
    'DOMAIN-SUFFIX,tenpay.com,DIRECT',
    'DOMAIN-SUFFIX,qpic.cn,DIRECT',
    'DOMAIN-SUFFIX,qlogo.cn,DIRECT',
    // 2. 广告拦截(anti-AD中文区 + MetaCubeX国际, 互补)
    'RULE-SET,ads_antiad,🛑 广告拦截',
    'RULE-SET,ads_all,🛑 广告拦截',
    // 3. 国际 AI 服务(国内AI由 cn_domain 兜底直连)
    'RULE-SET,ai_global,🤖 AI服务',
    // 4. Telegram
    'RULE-SET,telegram,📱 Telegram',
    'RULE-SET,telegram_ip,📱 Telegram,no-resolve',
    // 5. 流媒体全家桶
    'RULE-SET,netflix,📺 Netflix',
    'RULE-SET,netflix_ip,📺 Netflix',
    'RULE-SET,primevideo,📺 Prime Video',
    'RULE-SET,disney,🎬 Disney+',
    'RULE-SET,youtube,▶️ YouTube',
    'RULE-SET,spotify,🎵 Spotify',
    'RULE-SET,bilibili,📺 B站',
    'RULE-SET,tiktok,🎵 TikTok',
    'RULE-SET,twitter,𝕏 Twitter',
    // 6. 平台服务(GitHub 必须在微软之前, 否则被微软组吃走)
    'RULE-SET,github,🚀 节点选择',
    'RULE-SET,microsoft,Ⓜ️ 微软服务',
    'RULE-SET,apple,🍎 苹果服务',
    'RULE-SET,google,🔍 谷歌服务',
    'RULE-SET,game_platforms,🎮 游戏平台',
    // 7. 国内直连
    'RULE-SET,cn_domain,🇨🇳 国内直连',
    'RULE-SET,cn_ip,🇨🇳 国内直连,no-resolve',
    // 8. 已知国外域名兜底
    'RULE-SET,proxy_domain,🚀 节点选择',
    // 9. 终极兜底
    'MATCH,🐟 漏网之鱼'
  ];

  return config;
}
