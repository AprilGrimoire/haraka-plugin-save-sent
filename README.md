# haraka-plugin-save-sent

A Haraka mail plugin that duplicates submitted emails to the sender with a special header, intended to be placed in a "Sent" mailbox by a sieve filter or similar mail filtering mechanism.

## Overview

When users send emails through your Haraka mail server, this plugin automatically creates a duplicate of each outbound email and sends it back to the sender. The duplicate email includes special headers that can be used by sieve filters to automatically file the message into a "Sent" folder, allowing email clients to maintain a proper sent mail history.

### How It Works

1. **Security Token Generation**: When an email is queued for delivery (`queue_ok` hook), the plugin generates a random security token and stores a "shape" (some stable email headers) in Redis with a 60-second expiration.

2. **Email Duplication**: The plugin creates a duplicate of the outbound email, adds special headers (a duplicate flag and security token), and sends it back to the original sender.

3.1. **Local Delivery**: If the duplicate email is configured to be delivered locally (for example, via LMTP), the security token isn't inspected and the item in Redis will expire.

3.2.1 **Security Verification**: When the duplicate email arrives back at the server (`data_post` hook), the plugin verifies the security token matches the stored shape to prevent header spoofing or malicious attempts.

3.2.2. **Header Cleanup**: After verification, the security token header is removed before final delivery.

4. **Sieve Filtering**: A sieve filter can then detect the special header (`X-Save_to_mailbox: ServerSent` by default) and file the message into the appropriate Sent folder.

## Requirements

- **Haraka** mail server
- **Redis** server (for security token storage)
- **haraka-plugin-redis** (or similar) to provide Redis connectivity

## Installation

```bash
npm install https://github.com/AprilGrimoire/haraka-plugin-save-sent
```

## Configuration

### 1. Enable the Plugin

Add `save_sent` to your `config/plugins` file:

```
# other plugins...
save_sent
```

### 2. Configure Redis

Ensure Redis is configured and available via `server.notes.redis`. This typically requires installing and configuring a Redis plugin like `haraka-plugin-redis`.

### 3. Plugin Configuration

See `config/save_sent.hjson`.

## Sieve Filter Example

To automatically file duplicated emails into a Sent folder, use a sieve filter like this:

```sieve
require ["fileinto"];

if header :is "X-Save_to_mailbox" "ServerSent" {
    fileinto "ServerSent";
    stop;
}
```

## Security

The plugin implements security measures to prevent header spoofing:

- **Shape Verification**: The plugin calculates a "shape" from stable email headers (From, To, Cc, Subject, Date) and stores it in Redis with the security token. _I would also like to store (the hash of) the body, but there isn't an exposed interface for this, so the body isn't verified for now. But since the security token likely wouldn't be exposed, I believe this isn't a major security issue._
- **Token Validation**: When the duplicate email returns, the plugin verifies that the security token matches the stored shape.
- **Token Expiration**: Security tokens expire after 60 seconds in Redis.
- **Header Removal**: The security token header is removed before final delivery.

If an email arrives with the duplicate flag header but without a valid security token, the email is rejected to prevent potential abuse.

## Limitations

- Currently duplicates **all** outbound emails to the sender. This behavior may not be suitable if Haraka is used as a relay for multiple domains.
- Requires Redis to be available; emails will be rejected if Redis is down during processing. This might not be necessary. Initially I thought the internally generated mails would also go through the usual inbound route, however it turned out that is often (if not always) not the case. Since Haraka supports swarm mode, I'm not making the assumption that the duplicated mail wouldn't go through SMTP. **Though if you want to use this plugin and don't want to enable Redis, let me know. This plugin is currently in a very primitive state, so no-Redis support would likely be added later.**

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Author

AprilGrimoire (april@aprilg.moe)

## Contributing

Issues and pull requests are welcome at [https://github.com/AprilGrimoire/haraka-plugin-save-sent](https://github.com/AprilGrimoire/haraka-plugin-save-sent).
