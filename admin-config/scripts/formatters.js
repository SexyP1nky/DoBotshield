(function attachFormatters(global) {
  "use strict";

  function normalizeConfig(config) {
    return {
      targetUrl: trimValue(config.targetUrl),
      proxyPort: trimValue(config.proxyPort),
      enableWaf: trimValue(config.enableWaf),
      wafMode: trimValue(config.wafMode),
      enableResponseInspection: trimValue(config.enableResponseInspection),
      enableRateLimit: trimValue(config.enableRateLimit),
      rateLimit: trimValue(config.rateLimit),
      burstLimit: trimValue(config.burstLimit),
      maxConns: trimValue(config.maxConns),
      maxTrackedIps: trimValue(config.maxTrackedIps),
      maxBodySize: trimValue(config.maxBodySize),
      responseInspectionLimit: trimValue(config.responseInspectionLimit),
      certFile: trimValue(config.certFile),
      keyFile: trimValue(config.keyFile),
      trustedProxies: global.DoBotAdmin.splitCsv(config.trustedProxies).join(","),
      insecureSkipVerify: trimValue(config.insecureSkipVerify),
      wafAllowlist: global.DoBotAdmin.splitCsv(config.wafAllowlist).join(","),
      blockedIps: global.DoBotAdmin.splitCsv(config.blockedIps).join(","),
      rateLimitStateFile: trimValue(config.rateLimitStateFile)
    };
  }

  function trimValue(value) {
    return String(value || "").trim();
  }

  function toEnvPairs(config) {
    var normalizedConfig = normalizeConfig(config);

    return global.DoBotAdmin.CONFIG_FIELDS.map(function mapField(field) {
      return {
        key: field.env,
        value: normalizedConfig[field.id]
      };
    });
  }

  function buildAccessUrl(proxyPort) {
    var addr = String(proxyPort || ":443").trim();
    if (addr.charAt(0) === ":") {
      addr = "localhost" + addr;
    }
    return "https://" + addr;
  }

  function buildPowerShell(config) {
    var lines = toEnvPairs(config).map(function mapPair(pair) {
      return "$env:" + pair.key + " = " + quotePowerShell(pair.value);
    });

    lines.unshift("# Acesso: " + buildAccessUrl(config.proxyPort));
    lines.push(".\\dobotshield.exe");
    return lines.join("\n");
  }

  function buildBash(config) {
    var lines = toEnvPairs(config).map(function mapPair(pair) {
      return "export " + pair.key + "=" + quoteBash(pair.value);
    });

    lines.unshift("# Acesso: " + buildAccessUrl(config.proxyPort));
    lines.push("./dobotshield");
    return lines.join("\n");
  }

  function buildDotEnv(config) {
    var header = "# Acesso: " + buildAccessUrl(config.proxyPort);
    var body = toEnvPairs(config).map(function mapPair(pair) {
      return pair.key + "=" + quoteDotEnv(pair.value);
    }).join("\n");
    return header + "\n" + body;
  }

  function buildCommand(config, mode) {
    var builders = {
      powershell: buildPowerShell,
      bash: buildBash,
      dotenv: buildDotEnv
    };

    return builders[mode](config);
  }

  function quotePowerShell(value) {
    return "'" + String(value).replace(/'/g, "''") + "'";
  }

  function quoteBash(value) {
    return "'" + String(value).replace(/'/g, "'\\''") + "'";
  }

  function quoteDotEnv(value) {
    return '"' + String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
  }

  global.DoBotAdmin = Object.assign(global.DoBotAdmin || {}, {
    buildCommand: buildCommand,
    buildDotEnv: buildDotEnv,
    normalizeConfig: normalizeConfig
  });
})(window);
