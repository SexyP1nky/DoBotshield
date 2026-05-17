(function startAdminConfigurator(global) {
  "use strict";

  var activeMode = "powershell";

  function init() {
    var initialConfig = global.DoBotAdmin.loadSavedConfig() || global.DoBotAdmin.getDefaultConfig();

    global.DoBotAdmin.writeConfigToForm(initialConfig);
    bindEvents();
    refresh();
  }

  function bindEvents() {
    global.DoBotAdmin.getElement("#configForm").addEventListener("input", handleInput);
    global.DoBotAdmin.getElement("#configForm").addEventListener("submit", handleSubmit);
    global.DoBotAdmin.getElement('[data-action="reset"]').addEventListener("click", handleReset);
    global.DoBotAdmin.getElement('[data-action="copy"]').addEventListener("click", handleCopy);
    global.DoBotAdmin.getElement('[data-action="download"]').addEventListener("click", handleDownload);

    global.DoBotAdmin.getElements("[data-command-tab]").forEach(function bindTab(tab) {
      tab.addEventListener("click", handleTabClick);
    });
  }

  function handleInput() {
    var config = global.DoBotAdmin.readConfigFromForm();

    global.DoBotAdmin.saveConfig(config);
    refresh();
  }

  function handleSubmit(event) {
    event.preventDefault();

    var validation = refresh();

    if (!validation.isValid) {
      global.DoBotAdmin.focusFirstInvalid(validation);
    }
  }

  function handleReset() {
    global.DoBotAdmin.clearSavedConfig();
    global.DoBotAdmin.writeConfigToForm(global.DoBotAdmin.getDefaultConfig());
    refresh();
    setCopyStatus("");
  }

  function handleTabClick(event) {
    activeMode = event.currentTarget.dataset.commandTab;
    global.DoBotAdmin.renderActiveTab(activeMode);
    refresh();
  }

  function handleCopy() {
    var output = global.DoBotAdmin.getElement("#commandOutput");

    global.DoBotAdmin.copyText(output.value, output)
      .then(function showSuccess() {
        setCopyStatus("Conteudo copiado.");
      })
      .catch(function showFailure() {
        setCopyStatus("Nao foi possivel copiar automaticamente.");
      });
  }

  function handleDownload() {
    var config = global.DoBotAdmin.readConfigFromForm();
    var validation = global.DoBotAdmin.validateConfig(config);

    global.DoBotAdmin.renderValidation(validation);

    if (!validation.isValid) {
      global.DoBotAdmin.focusFirstInvalid(validation);
      return;
    }

    global.DoBotAdmin.downloadText("dobotshield.env", global.DoBotAdmin.buildDotEnv(config));
    setCopyStatus("Arquivo .env gerado.");
  }

  function refresh() {
    var config = global.DoBotAdmin.readConfigFromForm();
    var validation = global.DoBotAdmin.validateConfig(config);

    global.DoBotAdmin.renderValidation(validation);
    global.DoBotAdmin.renderCommand(config, activeMode);
    return validation;
  }

  function setCopyStatus(message) {
    global.DoBotAdmin.setText(global.DoBotAdmin.getElement("#copyStatus"), message);
  }

  document.addEventListener("DOMContentLoaded", init);
})(window);
