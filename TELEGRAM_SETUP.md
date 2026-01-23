# Telegram Alerts Setup

## 1. Create a Bot

1. Open Telegram and search for `@BotFather`
2. Send `/newbot`
3. Choose a name for your bot (e.g., "DHCP Watch")
4. Choose a username ending in `bot` (e.g., `dhcp_watch_alerts_bot`)
5. BotFather will reply with your bot token (looks like `123456789:ABCdefGHI...`)

## 2. Get Your Chat ID

1. Start a chat with your new bot (search for it and press Start)
2. Send any message to the bot
3. Run this command (replace `YOUR_BOT_TOKEN` with your actual token):

```bash
curl "https://api.telegram.org/botYOUR_BOT_TOKEN/getUpdates"
```

4. Find your chat ID in the response under `"chat":{"id":123456789}`

## 3. Configure

Copy the example config and add your credentials:

```bash
cp config.example.json config.json
```

Edit `config.json`:

```json
{
  "bot_token": "YOUR_BOT_TOKEN",
  "chat_id": "YOUR_CHAT_ID"
}
```

## 4. Test

Verify your setup with:

```bash
curl -X POST "https://api.telegram.org/botYOUR_BOT_TOKEN/sendMessage" \
  -d "chat_id=YOUR_CHAT_ID" \
  -d "text=Test message"
```

You should receive "Test message" in Telegram.
