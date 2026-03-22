(function () {
  'use strict';

  function supportsPasskeys() {
    return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create);
  }

  function unsupportedReason() {
    if (!window.isSecureContext) {
      return 'Passkeys require a secure context (HTTPS or localhost).';
    }
    if (!('PublicKeyCredential' in window)) {
      return 'This browser does not expose the WebAuthn API (PublicKeyCredential).';
    }
    if (!(navigator.credentials && navigator.credentials.create)) {
      return 'This browser does not support credential creation for passkeys.';
    }
    return (passkeyLoginRegister.i18n && passkeyLoginRegister.i18n.notSupported) || 'Passkeys are not supported on this browser.';
  }

  function endpoint(path) {
    const base = String(passkeyLoginRegister.restUrl || '').replace(/\/+$/, '');
    const tail = String(path || '').replace(/^\/+/, '');
    return `${base}/${tail}`;
  }

  function toBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (let i = 0; i < bytes.length; i += 1) {
      str += String.fromCharCode(bytes[i]);
    }
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  function fromBase64Url(value) {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padding = normalized.length % 4 ? '='.repeat(4 - (normalized.length % 4)) : '';
    const binary = atob(normalized + padding);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  async function callApi(path, body) {
    const response = await fetch(endpoint(path), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-WP-Nonce': passkeyLoginRegister.nonce,
      },
      credentials: 'same-origin',
      body: JSON.stringify(body || {}),
    });

    const data = await response.json();
    if (!response.ok || !data.success) {
      throw new Error((data && data.message) || passkeyLoginRegister.i18n.failed);
    }
    return data.data;
  }

  function setStatus(message, isError) {
    const node = document.getElementById('securekey-login-register-status');
    if (!node) {
      return;
    }
    node.style.display = 'block';
    node.textContent = message;
    node.style.color = isError ? '#b32d2e' : '#2271b1';
  }

  function askPasskeyName() {
    const promptText = (passkeyLoginRegister.i18n && passkeyLoginRegister.i18n.namePrompt)
      || 'Enter a name for this passkey';
    const defaultName = (passkeyLoginRegister.i18n && passkeyLoginRegister.i18n.nameDefault)
      || 'My Passkey';

    const value = window.prompt(promptText, defaultName);
    if (value === null) {
      return null;
    }

    const trimmed = String(value).trim();
    return trimmed || defaultName;
  }

  function shouldSilenceError(error) {
    const name = (error && error.name ? String(error.name) : '').toLowerCase();
    const msg = (error && error.message ? String(error.message) : '').toLowerCase();

    if (name === 'notallowederror' || name === 'aborterror') {
      return true;
    }

    return msg.includes('timed out or was not allowed') || msg.includes('not allowed') || msg.includes('operation either timed out');
  }

  async function registerPasskey() {
    if (!supportsPasskeys()) {
      setStatus(unsupportedReason(), true);
      return;
    }

    try {
      const passkeyName = askPasskeyName();
      if (passkeyName === null) {
        return;
      }

      const options = await callApi('register/begin');
      options.challenge = fromBase64Url(options.challenge);
      options.user.id = fromBase64Url(options.user.id);
      options.excludeCredentials = (options.excludeCredentials || []).map((cred) => ({
        ...cred,
        id: fromBase64Url(cred.id),
      }));

      const credential = await navigator.credentials.create({ publicKey: options });
      if (!credential) {
        throw new Error(passkeyLoginRegister.i18n.failed);
      }

      const payload = {
        id: credential.id,
        rawId: toBase64Url(credential.rawId),
        type: credential.type,
        challenge: toBase64Url(options.challenge),
        origin: window.location.origin,
        name: passkeyName,
        response: {
          attestationObject: toBase64Url(credential.response.attestationObject),
          clientDataJSON: toBase64Url(credential.response.clientDataJSON),
          transports: credential.response.getTransports ? credential.response.getTransports() : [],
        },
      };

      await callApi('register/complete', { credential: payload });
      setStatus(passkeyLoginRegister.i18n.success, false);
      window.location.reload();
    } catch (error) {
      if (shouldSilenceError(error)) {
        return;
      }
      setStatus(error.message || passkeyLoginRegister.i18n.failed, true);
    }
  }

  document.addEventListener('click', function (event) {
    if (event.target && event.target.id === 'securekey-login-register') {
      event.preventDefault();
      registerPasskey();
    }
  });

  document.addEventListener('click', async function (event) {
    const target = event.target;
    if (!target || !target.classList || !target.classList.contains('securekey-login-delete-passkey')) {
      return;
    }

    event.preventDefault();
    const credentialId = target.getAttribute('data-credential-id');
    if (!credentialId) {
      return;
    }

    try {
      const response = await fetch(endpoint(`credentials/${credentialId}`), {
        method: 'DELETE',
        headers: {
          'X-WP-Nonce': passkeyLoginRegister.nonce,
        },
        credentials: 'same-origin',
      });

      const data = await response.json();
      if (!response.ok || !data.success) {
        throw new Error(passkeyLoginRegister.i18n.failed);
      }

      window.location.reload();
    } catch (error) {
      setStatus(error.message || passkeyLoginRegister.i18n.failed, true);
    }
  });
})();
