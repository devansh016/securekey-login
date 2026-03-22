(function () {
  'use strict';

  function supportsPasskeys() {
    return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.get);
  }

  function unsupportedReason() {
    if (!window.isSecureContext) {
      return 'Passkeys require a secure context (HTTPS or localhost).';
    }
    if (!('PublicKeyCredential' in window)) {
      return 'This browser does not expose the WebAuthn API (PublicKeyCredential).';
    }
    if (!(navigator.credentials && navigator.credentials.get)) {
      return 'This browser does not support credential authentication for passkeys.';
    }
    return (passkeyLoginAuth.i18n && passkeyLoginAuth.i18n.notSupported) || 'Passkeys are not supported on this browser.';
  }

  function endpoint(path) {
    const base = String(passkeyLoginAuth.restUrl || '').replace(/\/+$/, '');
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

  async function api(path, body) {
    const response = await fetch(endpoint(path), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-WP-Nonce': passkeyLoginAuth.nonce,
      },
      credentials: 'same-origin',
      body: JSON.stringify(body || {}),
    });

    const data = await response.json();
    if (!response.ok || !data.success) {
      throw new Error((data && data.message) || passkeyLoginAuth.i18n.failed);
    }

    return data.data;
  }

  function setStatus(message, isError) {
    const statusNode = document.getElementById('securekey-login-status');
    if (!statusNode) {
      return;
    }
    statusNode.style.display = 'block';
    statusNode.textContent = message;
    statusNode.style.color = isError ? '#b32d2e' : '#2271b1';
  }

  function shouldSilenceError(error) {
    const name = (error && error.name ? String(error.name) : '').toLowerCase();
    const msg = (error && error.message ? String(error.message) : '').toLowerCase();

    if (name === 'notallowederror' || name === 'aborterror') {
      return true;
    }

    return msg.includes('timed out or was not allowed') || msg.includes('not allowed') || msg.includes('operation either timed out');
  }

  async function authenticate() {
    if (!supportsPasskeys()) {
      setStatus(unsupportedReason(), true);
      return;
    }

    try {
      const username = document.getElementById('user_login') ? document.getElementById('user_login').value : '';
      const options = await api('authenticate/begin', { username });

      options.challenge = fromBase64Url(options.challenge);
      options.allowCredentials = (options.allowCredentials || []).map((cred) => ({
        ...cred,
        id: fromBase64Url(cred.id),
      }));

      const assertion = await navigator.credentials.get({ publicKey: options });
      if (!assertion) {
        throw new Error(passkeyLoginAuth.i18n.failed);
      }

      const payload = {
        id: assertion.id,
        rawId: toBase64Url(assertion.rawId),
        type: assertion.type,
        challenge: toBase64Url(options.challenge),
        origin: window.location.origin,
        response: {
          authenticatorData: toBase64Url(assertion.response.authenticatorData),
          clientDataJSON: toBase64Url(assertion.response.clientDataJSON),
          signature: toBase64Url(assertion.response.signature),
          userHandle: assertion.response.userHandle ? toBase64Url(assertion.response.userHandle) : '',
        },
      };

      const input = document.getElementById('securekey-login-assertion');
      if (input) {
        input.value = JSON.stringify(payload);
      }

      const form = document.getElementById('loginform');
      if (form) {
        form.submit();
      }
    } catch (error) {
      if (shouldSilenceError(error)) {
        return;
      }
      setStatus(error.message || passkeyLoginAuth.i18n.failed, true);
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    const button = document.getElementById('securekey-login-login');
    if (!button) {
      return;
    }

    button.addEventListener('click', function (event) {
      event.preventDefault();
      authenticate();
    });
  });
})();
