import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, api } from './api';

interface FakeResponseOptions {
  ok?: boolean;
  status?: number;
  statusText?: string;
  json?: () => Promise<unknown>;
  text?: () => Promise<string>;
}

function fakeResponse(options: FakeResponseOptions = {}): Response {
  return {
    ok: options.ok ?? true,
    status: options.status ?? 200,
    statusText: options.statusText ?? 'OK',
    json: options.json ?? (async () => ({})),
    text: options.text ?? (async () => ''),
  } as unknown as Response;
}

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

async function captureApiError(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    return error as ApiError;
  }
  throw new Error('Expected the API call to reject');
}

describe('api client', () => {
  it('returns parsed JSON and requests the expected endpoint', async () => {
    const engagements = [
      {
        id: 'eng-1',
        workspaceId: 'ws-1',
        name: 'Acme',
        status: 'active',
        createdAt: '2026-01-01T00:00:00Z',
      },
    ];
    fetchMock.mockResolvedValueOnce(
      fakeResponse({ json: async () => engagements }),
    );

    await expect(api.getEngagements()).resolves.toEqual(engagements);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/engagements');
    expect(fetchMock.mock.calls[0][1].signal).toBeInstanceOf(AbortSignal);
  });

  it('returns the health payload when the backend is healthy', async () => {
    const health = {
      status: 'healthy',
      service: 'alltools',
      timestamp: '2026-01-01T00:00:00Z',
      version: '0.1.0',
    };
    fetchMock.mockResolvedValueOnce(fakeResponse({ json: async () => health }));

    await expect(api.getHealth()).resolves.toEqual(health);
    expect(fetchMock.mock.calls[0][0]).toBe('/health');
  });

  it('rejects an unhealthy health response as an ApiError', async () => {
    fetchMock.mockResolvedValueOnce(
      fakeResponse({
        json: async () => ({
          status: 'degraded',
          service: 'alltools',
          timestamp: '2026-01-01T00:00:00Z',
          version: '0.1.0',
        }),
      }),
    );

    const error = await captureApiError(api.getHealth());

    expect(error).toBeInstanceOf(ApiError);
    expect(error.message).toBe("Health check returned status 'degraded'.");
    expect(error.status).toBe(200);
    expect(error.endpoint).toBe('/health');
  });

  it('uses the JSON detail from a failed response', async () => {
    fetchMock.mockResolvedValueOnce(
      fakeResponse({
        ok: false,
        status: 404,
        statusText: 'Not Found',
        json: async () => ({ detail: 'Engagement not found' }),
      }),
    );

    const error = await captureApiError(api.getEngagements());

    expect(error).toBeInstanceOf(ApiError);
    expect(error.message).toBe('Engagement not found');
    expect(error.status).toBe(404);
    expect(error.endpoint).toBe('/api/v1/engagements');
  });

  it('falls back to the status text for a non-JSON error body', async () => {
    fetchMock.mockResolvedValueOnce(
      fakeResponse({
        ok: false,
        status: 502,
        statusText: 'Bad Gateway',
        json: async () => {
          throw new SyntaxError('Unexpected token <');
        },
      }),
    );

    const error = await captureApiError(api.getEngagements());

    expect(error).toBeInstanceOf(ApiError);
    expect(error.message).toBe('Bad Gateway');
    expect(error.status).toBe(502);
    expect(error.endpoint).toBe('/api/v1/engagements');
  });

  it('rejects invalid JSON from a successful response', async () => {
    fetchMock.mockResolvedValueOnce(
      fakeResponse({
        json: async () => {
          throw new SyntaxError('Unexpected end of JSON input');
        },
      }),
    );

    const error = await captureApiError(api.getEngagements());

    expect(error).toBeInstanceOf(ApiError);
    expect(error.message).toBe('Backend returned an invalid JSON response.');
    expect(error.status).toBe(200);
    expect(error.endpoint).toBe('/api/v1/engagements');
  });

  it('aborts a request after the endpoint timeout', async () => {
    vi.useFakeTimers();
    fetchMock.mockImplementation(
      (_input: RequestInfo | URL, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => {
            reject(new DOMException('The operation was aborted.', 'AbortError'));
          });
        }),
    );

    const result = captureApiError(api.getHealth());

    await vi.advanceTimersByTimeAsync(3999);
    expect(fetchMock.mock.calls[0][1].signal.aborted).toBe(false);

    await vi.advanceTimersByTimeAsync(1);
    const error = await result;

    expect(error.name).toBe('AbortError');
    expect(fetchMock.mock.calls[0][1].signal.aborted).toBe(true);
  });

  it('sends JSON headers and a body for create helpers', async () => {
    fetchMock.mockResolvedValueOnce(
      fakeResponse({
        json: async () => ({
          id: 'eng-1',
          workspaceId: 'ws-1',
          name: 'New engagement',
          status: 'active',
          createdAt: '2026-01-01T00:00:00Z',
        }),
      }),
    );

    await api.createEngagement({ name: 'New engagement' });

    const [, init] = fetchMock.mock.calls[0];
    expect(init.method).toBe('POST');
    expect(init.headers).toEqual({ 'Content-Type': 'application/json' });
    expect(JSON.parse(String(init.body))).toEqual({ name: 'New engagement' });
  });

  it('sends the supplied idempotency key and body id when running a check', async () => {
    fetchMock.mockResolvedValueOnce(
      fakeResponse({ json: async () => ({ allowed: true, message: 'ok' }) }),
    );

    await api.runCheck(
      'asmt-1',
      'rule-1',
      'example.com',
      { port: 443 },
      'CHK-fixed',
    );

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('/api/v1/executions/run');
    expect(init.headers).toEqual({
      'Content-Type': 'application/json',
      'Idempotency-Key': 'CHK-fixed',
    });
    expect(JSON.parse(String(init.body))).toEqual({
      id: 'CHK-fixed',
      assessmentId: 'asmt-1',
      ruleId: 'rule-1',
      target: 'example.com',
      simulatedData: { port: 443 },
    });
  });

  it('adds engagement and assessment filters to list endpoints', async () => {
    fetchMock
      .mockResolvedValueOnce(fakeResponse({ json: async () => [] }))
      .mockResolvedValueOnce(fakeResponse({ json: async () => [] }));

    await api.getAssessments('eng-1');
    await api.getExecutions('asmt-1');

    expect(fetchMock.mock.calls[0][0]).toBe(
      '/api/v1/assessments?engagementId=eng-1',
    );
    expect(fetchMock.mock.calls[1][0]).toBe(
      '/api/v1/executions?assessment_id=asmt-1',
    );
  });

  it('encodes evidence filter parameters', async () => {
    fetchMock.mockResolvedValueOnce(fakeResponse({ json: async () => [] }));

    await api.getEvidence('asmt 1', 'finding/1');

    expect(fetchMock.mock.calls[0][0]).toBe(
      '/api/v1/evidence?assessmentId=asmt+1&findingId=finding%2F1',
    );
  });

  it('returns report text from the markdown and html endpoints', async () => {
    fetchMock
      .mockResolvedValueOnce(
        fakeResponse({ text: async () => '# Assessment report' }),
      )
      .mockResolvedValueOnce(
        fakeResponse({ text: async () => '<h1>Assessment report</h1>' }),
      );

    await expect(api.getReportMarkdown('asmt-1')).resolves.toBe(
      '# Assessment report',
    );
    await expect(api.getReportHtml('asmt-1')).resolves.toBe(
      '<h1>Assessment report</h1>',
    );

    expect(fetchMock.mock.calls[0][0]).toBe(
      '/api/v1/reports/asmt-1/markdown',
    );
    expect(fetchMock.mock.calls[1][0]).toBe('/api/v1/reports/asmt-1/html');
  });

  it('throws ApiError when a report request fails', async () => {
    fetchMock.mockResolvedValueOnce(
      fakeResponse({
        ok: false,
        status: 503,
        statusText: 'Service Unavailable',
        text: async () => 'not available',
      }),
    );

    const error = await captureApiError(api.getReportMarkdown('asmt-1'));

    expect(error).toBeInstanceOf(ApiError);
    expect(error.message).toBe('Service Unavailable');
    expect(error.status).toBe(503);
    expect(error.endpoint).toBe('/api/v1/reports/asmt-1/markdown');
  });
});
