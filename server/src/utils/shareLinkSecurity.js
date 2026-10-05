import AppError from './AppError.js';

const localHosts = new Set(['localhost', '127.0.0.1']);

export const assertTrustedShareLink = (shareLink) => {
  let parsedUrl;

  try {
    parsedUrl = new URL(shareLink);
  } catch {
    throw new AppError('Enter a valid SecureShare link', 400);
  }

  const configuredUrl = process.env.APP_URL;

  if (!configuredUrl) {
    throw new AppError('SecureShare link validation is not configured', 500);
  }

  const configuredHost = new URL(configuredUrl).host;
  const isLocalHost = localHosts.has(parsedUrl.hostname);
  const isTrustedHost = parsedUrl.host === configuredHost || isLocalHost;
  const isSecure = parsedUrl.protocol === 'https:' || isLocalHost;

  if (!isTrustedHost || !isSecure) {
    throw new AppError('Only SecureShare links from a trusted host are allowed', 400);
  }

  const segments = parsedUrl.pathname.split('/').filter(Boolean);

  if (segments.length !== 2 || segments[0] !== 'share' || !segments[1]) {
    throw new AppError('Enter a valid SecureShare link', 400);
  }

  return segments[1];
};
