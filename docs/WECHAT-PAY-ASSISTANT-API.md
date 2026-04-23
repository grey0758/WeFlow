# WeChat Pay Assistant API

This endpoint is a focused API for WeChat Pay Assistant related local records.

```http
GET /api/v1/wechat-pay-assistant
```

## What It Returns

It returns records recoverable from the current local data layer for:

- `gh_f0a92aa7146c` (`微信收款助手`)
- `gh_3dfda90e39d6` (`微信支付`)
- hidden system holder sessions such as `brandservicesessionholder`

At the moment, this endpoint uses hidden session summaries as the recovery source when full message history is not available.

## Query Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `amount` | No | Numeric amount filter such as `3` or `3.00` |
| `merchant` | No | Merchant keyword filter, searched only against the currently recoverable summary text |
| `shop` | No | Alias of `merchant` |
| `limit` | No | Max rows to return, default `100` |

## Examples

```bash
curl "http://127.0.0.1:5031/api/v1/wechat-pay-assistant"
curl "http://127.0.0.1:5031/api/v1/wechat-pay-assistant?amount=3"
curl "http://127.0.0.1:5031/api/v1/wechat-pay-assistant?amount=3&merchant=opencodex"
```

## Response Fields

- `success`
- `recoveredFrom`
- `amountFilter`
- `merchantFilter`
- `count`
- `officialAccounts`
- `records`
- `notes`

Each `records[]` item contains:

- `username`
- `displayName`
- `summary`
- `category`
- `reason`
- `contactType`
- `unreadCount`
- `lastTimestamp`
- `parsedAmount`
- `amountMatched`
- `merchantMatched`
- `messageHistoryAvailable`
- `source`

## Important Limitation

- `messageHistoryAvailable: false` means the current project could not recover full payment message history from the local database layer.
- If `merchant=opencodex` returns no rows, that means the merchant name is not present in the currently recoverable summary text, not necessarily that the payment never existed.
