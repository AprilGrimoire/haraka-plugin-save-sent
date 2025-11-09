const crypto = require('crypto');

exports.register = function () {
  this.load_save_sent_hjson();
  this.outbound = this.haraka_require('outbound');

  this.register_hook('data_post', 'security_inspection');
  this.register_hook('queue_ok', 'duplicate_to_sender');
};

exports.load_save_sent_hjson = function () {
  this.cfg = this.config.get('save_sent.hjson', () => {
    this.load_save_sent_hjson();
  });
  this.loginfo('Loaded config');
};

// Maintain header_flag and security_token
exports.security_inspection = function (next, connection) {
  (async () => {
    if (!this.ensure_redis()) {
      this.logcrit("Redis not available");
      return next(DENY, "Internal server error");
    }

    // Security token must be correct and some stable items of headers
    // must match the stored value for internal flag duplicate_to_sender_flag
    // to be allowed.
    let verified_security_token = false;
    let header_items_security_token = connection.transaction.header.get_all(this.cfg.security_token_name);
    if (header_items_security_token.length != 0) {
      // No more than 1 token header item should appear,
      // but in case otherwise, this would fail normally.
      const token = header_items_security_token.join("\n");
      const shape_stored = await server.notes.redis.get(`${this.cfg.redis_hash_name}:${token}`);
      const shape_inbound = calculate_shape(connection.transaction.header);

      if (shape_stored === shape_inbound) {
        verified_security_token = true;
        await server.notes.redis.del(`${this.cfg.redis_hash_name}:${token}`);
      } else {
        this.loginfo(
          "Verification of security token failed. This could be a plugin bug (most likely) or a malicious attempt."
        );
      }

      // Security header is internal and should not live to delivery
      connection.transaction.remove_header(this.cfg.security_token_name);
    }

    let header_items_duplicate_flag = connection.transaction.header.get_all(this.cfg.duplicate_to_sender_flag_name);

    if (header_items_duplicate_flag.length != 0) {
      if (!verified_security_token) {
        this.logwarn(
          `Disallowed header item ${this.cfg.duplicate_to_sender_flag_name}. This could be a plugin bug (most likely) or a malicious attempt.`
        );
        return next(DENY);
      }
      if (header_items_duplicate_flag.length != 1) {
        this.logcrit(
          `Header item ${this.cfg.duplicate_to_sender_flag_name} should not appear more than once: ${header_items_duplicate_flag}`
        );
        return next(DENY, "Internal server error");
      }
    }

    return next();
  })();
}

exports.duplicate_to_sender = function (next, connection) {
  if (!this.ensure_redis()) {
    this.logcrit("Redis is not available!");
    return next(DENY, "Internal server error");
  }

  if (connection.transaction.header.get_all(this.cfg.duplicate_to_sender_flag_name).length) {
    this.logdebug("Will not duplicate to sender a mail that is already a duplicate.");
    return next();
  }

  // Currently we duplicate all outbound mails to sender.
  // This might not make sense if Haraka is working as a relay.
  const cfg = this.cfg;
  const outbound = this.outbound;
  // Duplicate the outbound mail
  // and add headers to mark it as duplicated
  connection.transaction.message_stream.get_data(
    raw => {
      (async () => {
        const full_text = raw.toString("utf8");
        const separator_index = full_text.search(/\r?\n\r?\n/);
        const body_text = full_text.substring(separator_index).replace(/^\r?\n\r?\n/, '');
        const header_items = connection.transaction.header.lines();
        const email_shape = calculate_shape(connection.transaction.header);
        const token = crypto.randomBytes(32).toString('hex');
        await server.notes.redis.set(`${cfg.redis_hash_name}:${token}`, email_shape, { EX : 60 });
        header_items.push(`${cfg.duplicate_to_sender_flag_name}: ${cfg.duplicate_to_sender_flag_value}`);
        header_items.push(`${cfg.security_token_name}: ${token}`);
        const duplicate_full_text = header_items.join('\r\n') + '\r\n\r\n' + body_text;
        outbound.send_email(
          connection.transaction.header.get('From'),
          connection.transaction.header.get('To'),
          duplicate_full_text
        );
      })();
    }
  );
  return next();
}

exports.ensure_redis = function () {
  if (!server.notes.redis) {
    this.logcrit("Redis is not available!");
    return false;
  }
  return true;
}

// Extract stable header items that shouldn't be overwritten in transmission
// to an object from a haraka header object,
// filling undefined fields with "".
function extract_stable_headers (header) {
  const list_of_stable = ["From", "To", "Cc", "Subject", "Date"];
  let result = {};
  for (const i of list_of_stable) {
    let x = header.get(i);
    result[i] = x ? x : "";
  }
  return result;
}

// For an object m with keys and values all strings, compute its canonical form.
function canonical_string (o) {
  let l = [];
  for (const [key, value] of Object.entries(o)) {
    l.push([key, value]);
  }
  l.sort();
  return JSON.stringify(l);
}

// The shape of a mail determined by its header
// to ensure the integrity of duplicated mails.
function calculate_shape (header) {
  return canonical_string(extract_stable_headers(header));
}
