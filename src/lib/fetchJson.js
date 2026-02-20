function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function isAbortError(error) {
  return error instanceof DOMException && error.name === 'AbortError';
}

function createTimedSignal(parentSignal, timeoutMs) {
  const controller = new AbortController();
  const onAbort = () => controller.abort();

  if (parentSignal) {
    if (parentSignal.aborted) {
      controller.abort();
    } else {
      parentSignal.addEventListener('abort', onAbort, { once: true });
    }
  }

  const timeoutId = setTimeout(() => {
    controller.abort();
  }, timeoutMs);

  return {
    signal: controller.signal,
    cleanup() {
      clearTimeout(timeoutId);
      if (parentSignal) {
        parentSignal.removeEventListener('abort', onAbort);
      }
    },
  };
}

export async function fetchJson(
  url,
  { timeoutMs = 5000, retries = 1, retryDelayMs = 250, signal, headers, ...options } = {},
) {
  let lastError;

  for (let attempt = 0; attempt <= retries; attempt += 1) {
    if (signal?.aborted) {
      throw new DOMException('Request aborted', 'AbortError');
    }

    const timed = createTimedSignal(signal, timeoutMs);

    try {
      const response = await fetch(url, {
        ...options,
        headers,
        signal: timed.signal,
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      lastError = error;

      if (isAbortError(error)) {
        throw error;
      }

      if (attempt < retries) {
        const backoff = retryDelayMs * 2 ** attempt;
        await sleep(backoff);
      }
    } finally {
      timed.cleanup();
    }
  }

  throw lastError || new Error(`Failed to fetch ${url}`);
}
