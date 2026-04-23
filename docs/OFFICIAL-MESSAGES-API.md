# Official Messages API

This project already exposes a generic messages endpoint:

```http
GET /api/v1/messages?talker=<session-id>
```

For official accounts such as `WeChat Pay Assistant`, a dedicated endpoint is now available:

```http
GET /api/v1/official-messages
```

## Purpose

`/api/v1/sessions` does not list official accounts by default, but the project can still read their local message history from the WeChat desktop database. This endpoint resolves the official account first, then reuses the existing message API logic.

## Query Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `username` | No | Exact official account username, for example `gh_xxx` |
| `talker` | No | Alias of `username` |
| `name` | No | Fuzzy match against `displayName`, `nickname`, `remark`, `alias`, or `username` |
| `officialName` | No | Alias of `name` |
| `limit` | No | Same as `/api/v1/messages`, default `100` |
| `offset` | No | Same as `/api/v1/messages`, default `0` |
| `start` | No | Same as `/api/v1/messages` |
| `end` | No | Same as `/api/v1/messages` |
| `keyword` | No | Message content filter, same as `/api/v1/messages` |
| `format` | No | `json` or `chatlab` |
| `chatlab` | No | Alias of `format=chatlab` |
| `media` | No | Whether to export media, same as `/api/v1/messages` |
| `image` | No | Same as `/api/v1/messages` |
| `voice` | No | Same as `/api/v1/messages` |
| `video` | No | Same as `/api/v1/messages` |
| `emoji` | No | Same as `/api/v1/messages` |

At least one of `username` / `talker` / `name` / `officialName` is required.

## Examples

```bash
curl "http://127.0.0.1:5031/api/v1/official-messages?name=pay-assistant&limit=20"
curl "http://127.0.0.1:5031/api/v1/official-messages?username=gh_xxx&start=20260101&end=20260131"
curl "http://127.0.0.1:5031/api/v1/official-messages?name=pay-assistant&keyword=payment&format=chatlab"
```

## Response Behavior

- If the official account is resolved successfully, the response body is the same as `/api/v1/messages`.
- If no official account matches, the API returns `404`.
- If multiple official accounts match the provided `name`, the API returns `409` with a `candidates` array so the caller can choose one exact username.

## Notes

- The project reads local WeChat desktop data. If the official account history is not present in the local database, the API cannot return it.
- This is not a WeChat official platform API. It depends on your local desktop WeChat data being available and decryptable by WeFlow.
