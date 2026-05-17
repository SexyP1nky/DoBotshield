(function attachConfigSchema(global) {
  "use strict";

  var DEFAULT_CONFIG = {
    targetUrl: "http://localhost:4280",
    proxyPort: ":443",
    enableWaf: "true",
    wafMode: "block",
    enableResponseInspection: "true",
    enableRateLimit: "true",
    rateLimit: "10.0",
    burstLimit: "20",
    maxConns: "10",
    maxTrackedIps: "10000",
    maxBodySize: "1048576",
    responseInspectionLimit: "1048576",
    certFile: "server.crt",
    keyFile: "server.key",
    trustedProxies: "127.0.0.1,::1",
    insecureSkipVerify: "false",
    wafAllowlist: "",
    blockedIps: "",
    rateLimitStateFile: ""
  };

  var CONFIG_FIELDS = [
    { id: "targetUrl", env: "TARGET_URL", defaultValue: DEFAULT_CONFIG.targetUrl },
    { id: "proxyPort", env: "PROXY_PORT", defaultValue: DEFAULT_CONFIG.proxyPort },
    { id: "enableWaf", env: "ENABLE_WAF", defaultValue: DEFAULT_CONFIG.enableWaf },
    { id: "wafMode", env: "WAF_MODE", defaultValue: DEFAULT_CONFIG.wafMode },
    { id: "enableResponseInspection", env: "ENABLE_RESPONSE_INSPECTION", defaultValue: DEFAULT_CONFIG.enableResponseInspection },
    { id: "enableRateLimit", env: "ENABLE_RATE_LIMIT", defaultValue: DEFAULT_CONFIG.enableRateLimit },
    { id: "rateLimit", env: "RATE_LIMIT", defaultValue: DEFAULT_CONFIG.rateLimit },
    { id: "burstLimit", env: "BURST_LIMIT", defaultValue: DEFAULT_CONFIG.burstLimit },
    { id: "maxConns", env: "MAX_CONNS", defaultValue: DEFAULT_CONFIG.maxConns },
    { id: "maxTrackedIps", env: "MAX_TRACKED_IPS", defaultValue: DEFAULT_CONFIG.maxTrackedIps },
    { id: "maxBodySize", env: "MAX_BODY_SIZE", defaultValue: DEFAULT_CONFIG.maxBodySize },
    { id: "responseInspectionLimit", env: "RESPONSE_INSPECTION_LIMIT", defaultValue: DEFAULT_CONFIG.responseInspectionLimit },
    { id: "certFile", env: "CERT_FILE", defaultValue: DEFAULT_CONFIG.certFile },
    { id: "keyFile", env: "KEY_FILE", defaultValue: DEFAULT_CONFIG.keyFile },
    { id: "trustedProxies", env: "TRUSTED_PROXIES", defaultValue: DEFAULT_CONFIG.trustedProxies },
    { id: "insecureSkipVerify", env: "INSECURE_SKIP_VERIFY", defaultValue: DEFAULT_CONFIG.insecureSkipVerify },
    { id: "wafAllowlist", env: "WAF_ALLOWLIST", defaultValue: DEFAULT_CONFIG.wafAllowlist },
    { id: "blockedIps", env: "BLOCKED_IPS", defaultValue: DEFAULT_CONFIG.blockedIps },
    { id: "rateLimitStateFile", env: "RATE_LIMIT_STATE_FILE", defaultValue: DEFAULT_CONFIG.rateLimitStateFile }
  ];

  function getDefaultConfig() {
    return Object.assign({}, DEFAULT_CONFIG);
  }

  global.DoBotAdmin = Object.assign(global.DoBotAdmin || {}, {
    CONFIG_FIELDS: CONFIG_FIELDS,
    getDefaultConfig: getDefaultConfig
  });
})(window);
