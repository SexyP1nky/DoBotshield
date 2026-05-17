(function attachValidators(global) {
  "use strict";

  function createResult(isValid, message) {
    return { isValid: isValid, message: message || "" };
  }

  function isBlank(value) {
    return String(value || "").trim() === "";
  }

  function validateTargetUrl(value) {
    var cleanValue = String(value || "").trim();

    if (isBlank(cleanValue)) {
      return createResult(false, "Informe a URL do sistema legado.");
    }

    try {
      var parsedUrl = new URL(cleanValue);
      if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
        return createResult(false, "Use http:// ou https://.");
      }
      return createResult(true);
    } catch (error) {
      return createResult(false, "URL invalida.");
    }
  }

  function validateProxyPort(value) {
    var cleanValue = String(value || "").trim();
    var match = cleanValue.match(/^(?:(?:[a-zA-Z0-9.-]+|\[[0-9a-fA-F:]+\]))?:([0-9]{1,5})$/);

    if (isBlank(cleanValue)) {
      return createResult(false, "Informe a porta de escuta.");
    }

    if (!match) {
      return createResult(false, "Use formato :443 ou host:porta.");
    }

    return validatePortNumber(match[1]);
  }

  function validatePortNumber(value) {
    var port = Number(value);

    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return createResult(false, "A porta deve ficar entre 1 e 65535.");
    }

    return createResult(true);
  }

  function validateDecimal(value, label) {
    var numberValue = Number(String(value || "").trim());

    if (!Number.isFinite(numberValue) || numberValue <= 0) {
      return createResult(false, label + " deve ser maior que zero.");
    }

    return createResult(true);
  }

  function validateInteger(value, label) {
    var numberValue = Number(String(value || "").trim());

    if (!Number.isInteger(numberValue) || numberValue < 1) {
      return createResult(false, label + " deve ser inteiro e maior que zero.");
    }

    return createResult(true);
  }

  function validateBoolean(value, label) {
    if (value === "true" || value === "false") {
      return createResult(true);
    }

    return createResult(false, label + " deve ser verdadeiro ou falso.");
  }

  function validateWafMode(value) {
    if (["block", "monitor", "off"].includes(String(value || "").trim())) {
      return createResult(true);
    }

    return createResult(false, "Modo WAF deve ser block, monitor ou off.");
  }

  function validatePath(value, label) {
    if (isBlank(value)) {
      return createResult(false, "Informe o " + label + ".");
    }

    return createResult(true);
  }

  function validateOptionalPath(value) {
    return createResult(true);
  }

  function validateOptionalCsv(value) {
    return createResult(true);
  }

  function validateTrustedProxies(value) {
    var items = splitCsv(value);

    if (items.length === 0) {
      return createResult(false, "Informe pelo menos um IP confiavel.");
    }

    var invalidItems = items.filter(function findInvalidIp(item) {
      return !isLikelyIp(item);
    });

    if (invalidItems.length > 0) {
      return createResult(false, "Revise IPs: " + invalidItems.join(", "));
    }

    return createResult(true);
  }

  function splitCsv(value) {
    return String(value || "")
      .split(",")
      .map(function trimItem(item) {
        return item.trim();
      })
      .filter(Boolean);
  }

  function isLikelyIp(value) {
    return isIPv4(value) || isIPv6Candidate(value) || isCIDR(value);
  }

  function isCIDR(value) {
    var parts = String(value || "").split("/");
    var prefix;

    if (parts.length !== 2) {
      return false;
    }

    prefix = Number(parts[1]);
    if (!Number.isInteger(prefix)) {
      return false;
    }

    if (isIPv4(parts[0])) {
      return prefix >= 0 && prefix <= 32;
    }

    if (isIPv6Candidate(parts[0])) {
      return prefix >= 0 && prefix <= 128;
    }

    return false;
  }

  function isIPv4(value) {
    var parts = String(value || "").split(".");

    if (parts.length !== 4) {
      return false;
    }

    return parts.every(function validatePart(part) {
      if (!/^\d{1,3}$/.test(part)) {
        return false;
      }

      var numberValue = Number(part);
      return numberValue >= 0 && numberValue <= 255;
    });
  }

  function isIPv6Candidate(value) {
    var cleanValue = String(value || "").trim();
    return cleanValue.includes(":") && /^[0-9a-fA-F:]+$/.test(cleanValue) && cleanValue.length <= 45;
  }

  function validateField(fieldId, value) {
    var validators = {
      targetUrl: validateTargetUrl,
      proxyPort: validateProxyPort,
      enableWaf: function validateEnableWaf(valueToCheck) {
        return validateBoolean(valueToCheck, "WAF ativo");
      },
      wafMode: validateWafMode,
      enableResponseInspection: function validateEnableResponse(valueToCheck) {
        return validateBoolean(valueToCheck, "Inspecao de resposta");
      },
      enableRateLimit: function validateEnableRateLimit(valueToCheck) {
        return validateBoolean(valueToCheck, "Rate limit ativo");
      },
      rateLimit: function validateRate(valueToCheck) {
        return validateDecimal(valueToCheck, "Requisicoes por segundo");
      },
      burstLimit: function validateBurst(valueToCheck) {
        return validateInteger(valueToCheck, "Pico permitido");
      },
      maxConns: function validateConnections(valueToCheck) {
        return validateInteger(valueToCheck, "Conexoes simultaneas");
      },
      maxTrackedIps: function validateTrackedIps(valueToCheck) {
        return validateInteger(valueToCheck, "IPs rastreados");
      },
      maxBodySize: function validateBodySize(valueToCheck) {
        return validateInteger(valueToCheck, "Body maximo");
      },
      responseInspectionLimit: function validateResponseLimit(valueToCheck) {
        return validateInteger(valueToCheck, "Limite de resposta");
      },
      certFile: function validateCert(valueToCheck) {
        return validatePath(valueToCheck, "arquivo do certificado");
      },
      keyFile: function validateKey(valueToCheck) {
        return validatePath(valueToCheck, "arquivo da chave privada");
      },
      trustedProxies: validateTrustedProxies,
      insecureSkipVerify: function validateInsecureSkipVerify(valueToCheck) {
        return validateBoolean(valueToCheck, "TLS inseguro do backend");
      },
      wafAllowlist: validateOptionalCsv,
      rateLimitStateFile: validateOptionalPath
    };

    return validators[fieldId](value);
  }

  function validateConfig(config) {
    var errors = {};

    global.DoBotAdmin.CONFIG_FIELDS.forEach(function validateKnownField(field) {
      var result = validateField(field.id, config[field.id]);
      if (!result.isValid) {
        errors[field.id] = result.message;
      }
    });

    return {
      isValid: Object.keys(errors).length === 0,
      errors: errors
    };
  }

  global.DoBotAdmin = Object.assign(global.DoBotAdmin || {}, {
    splitCsv: splitCsv,
    validateConfig: validateConfig,
    validateField: validateField
  });
})(window);
