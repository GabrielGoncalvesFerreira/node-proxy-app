const MOBILE_HINTS = ['mobile', 'app', 'native', 'expo-mobile', 'ios', 'android'];

function getHeader(headers = {}, name) {
  if (!headers) return undefined;
  const target = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === target) {
      return headers[key];
    }
  }
  return undefined;
}

export function getClientTypeFromHeaders(headers = {}) {
  const raw = getHeader(headers, 'x-client-type') ?? getHeader(headers, 'x-client-typ');
  if (!raw || typeof raw !== 'string') {
    return 'web';
  }

  const normalized = raw.trim().toLowerCase();
  if (MOBILE_HINTS.includes(normalized)) {
    return 'mobile';
  }

  return 'web';
}

export function isMobileClient(headers = {}) {
  return getClientTypeFromHeaders(headers) === 'mobile';
}
