using System.Collections.Concurrent;

namespace Identity.Keycloak.Admin;

/// <summary>Reuses one admin token per server, realm and credential until shortly before it expires.</summary>
public sealed class KeycloakAdminTokenCache
{
    public static readonly TimeSpan RefreshMargin = TimeSpan.FromSeconds(30);

    private readonly ConcurrentDictionary<string, CachedTokenSlot> _slots = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;

    public KeycloakAdminTokenCache(TimeProvider timeProvider) => _timeProvider = timeProvider;

    internal async Task<string> GetOrFetchAsync(string key, Func<CancellationToken, Task<KeycloakAdminAccessToken>> fetch, CancellationToken cancellationToken)
    {
        var slot = _slots.GetOrAdd(key, _ => new CachedTokenSlot());
        if (slot.TryGetUsable(_timeProvider.GetUtcNow(), out var cached))
            return cached;

        await slot.Gate.WaitAsync(cancellationToken);
        try
        {
            if (slot.TryGetUsable(_timeProvider.GetUtcNow(), out cached))
                return cached;
            var fetched = await fetch(cancellationToken);
            slot.Store(fetched.Value, _timeProvider.GetUtcNow() + fetched.Lifetime - RefreshMargin);
            return fetched.Value;
        }
        finally
        {
            slot.Gate.Release();
        }
    }

    private sealed class CachedTokenSlot
    {
        private volatile CachedToken? _current;

        public SemaphoreSlim Gate { get; } = new(1, 1);

        public bool TryGetUsable(DateTimeOffset now, out string token)
        {
            var current = _current;
            var usable = current is not null && now < current.RefreshAt;
            token = usable ? current!.Value : string.Empty;
            return usable;
        }

        public void Store(string token, DateTimeOffset refreshAt) => _current = new CachedToken(token, refreshAt);
    }

    private sealed record CachedToken(string Value, DateTimeOffset RefreshAt);
}
