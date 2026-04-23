# Session Summaries API

This endpoint exposes hidden session summaries that are filtered out from the normal `/api/v1/sessions` list, including:

- Official accounts such as `gh_xxx`
- System holders such as `brandservicesessionholder`, `brandsessionholder`, `notifymessage`

It is useful when WeChat keeps only the session preview text locally, but not the full message history.

```http
GET /api/v1/session-summaries
```

## Query Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `scope` | No | `all`, `official`, or `system`. Default `all` |
| `keyword` | No | Filter by username, display name, aliases, or summary text |
| `username` | No | Filter by username substring |
| `payOnly` | No | `1/true` to keep only payment-like summaries |
| `paymentOnly` | No | Alias of `payOnly` |
| `limit` | No | Max rows to return, default `100` |

## Example

```bash
curl "http://127.0.0.1:5031/api/v1/session-summaries?payOnly=1&limit=50"
curl "http://127.0.0.1:5031/api/v1/session-summaries?scope=official"
curl "http://127.0.0.1:5031/api/v1/session-summaries?keyword=pay"
curl "http://127.0.0.1:5031/api/v1/session-summaries?username=brandservicesessionholder"
```

## Response Fields

- `success`
- `count`
- `totalMatched`
- `scope`
- `payOnly`
- `categoryCounts`
- `sessions[]`

Each `sessions[]` item contains:

- `username`
- `talker`
- `displayName`
- `summary`
- `category`
- `reason`
- `contactType`
- `type`
- `unreadCount`
- `lastTimestamp`
- `payLike`
- `hasSummary`

## Notes

- This endpoint returns summary/session-layer data, not full message history.
- If a session has full messages available, `/api/v1/messages` should still be preferred for detail export.
