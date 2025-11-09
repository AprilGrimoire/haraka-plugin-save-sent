const crypto = require('crypto');

exports.register = function () {
  this.logdebug('=== Plugin registration starting ===');
  this.load_save_sent_hjson();
  this.outbound = this.haraka_require('outbound');
  this.logdebug('Outbound module loaded');

  this.register_hook('data_post', 'security_inspection');
  this.logdebug('Registered hook: data_post -> security_inspection');
  this.register_hook('queue_ok', 'duplicate_to_sender');
  this.logdebug('Registered hook: queue_ok -> duplicate_to_sender');
  this.logdebug('=== Plugin registration complete ===');
};

exports.load_save_sent_hjson = function () {
  this.logdebug('Loading save_sent.hjson configuration');
  this.cfg = this.config.get('save_sent.hjson', () => {
    this.logdebug('Config file changed, reloading');
    this.load_save_sent_hjson();
  });
  this.loginfo('Loaded config');
  this.logdebug(`Config details: ${JSON.stringify(this.cfg, null, 2)}`);
};

// Maintain header_flag and security_token
exports.security_inspection = function (next, connection) {
  this.logdebug('=== security_inspection hook called ===');
  (async () => {
    this.logdebug('Checking Redis availability');
    if (!this.ensure_redis()) {
      this.logcrit("Redis is not available!");
      return next(DENY, "Internal server error");
    }
    this.logdebug('Redis is available');

    // Security token must be correct and some stable items of headers
    // must match the stored value for internal flag duplicate_to_sender_flag
    // to be allowed.
    let verified_security_token = false;
    this.logdebug(`Looking for security token header: ${this.cfg.security_token_name}`);
    let header_items_security_token = connection.transaction.header.get_all(this.cfg.security_token_name);
    this.logdebug(`Found ${header_items_security_token.length} security token header(s)`);
    if (header_items_security_token.length != 0) {
      this.logdebug('Processing security token');
      // No more than 1 token header item should appear,
      // but in case otherwise, this would fail normally.
      const token = header_items_security_token.join("\n");
      this.logdebug(`Security token value: ${token}`);
      const redis_key = `${this.cfg.redis_hash_name}:${token}`;
      this.logdebug(`Looking up Redis key: ${redis_key}`);
      const shape_stored = await server.notes.redis.get(redis_key);
      this.logdebug(`Stored shape from Redis: ${shape_stored}`);
      const shape_inbound = calculate_shape(connection.transaction.header);
      this.logdebug(`Calculated inbound shape: ${shape_inbound}`);

      if (shape_stored === shape_inbound) {
        this.logdebug('Security token verification SUCCESSFUL - shapes match');
        verified_security_token = true;
        this.logdebug(`Deleting Redis key: ${redis_key}`);
        await server.notes.redis.del(redis_key);
      } else {
        this.logdebug('Security token verification FAILED - shapes do not match');
        this.loginfo(
          "Verification of security token failed. This could be a plugin bug (most likely) or a malicious attempt."
        );
      }

      // Security header is internal and should not live to delivery
      this.logdebug(`Removing security token header: ${this.cfg.security_token_name}`);
      connection.transaction.remove_header(this.cfg.security_token_name);
    } else {
      this.logdebug('No security token header found');
    }

    this.logdebug(`Looking for duplicate flag header: ${this.cfg.duplicate_to_sender_flag_name}`);
    let header_items_duplicate_flag = connection.transaction.header.get_all(this.cfg.duplicate_to_sender_flag_name);
    this.logdebug(`Found ${header_items_duplicate_flag.length} duplicate flag header(s)`);

    if (header_items_duplicate_flag.length != 0) {
      this.logdebug(`Duplicate flag header value(s): ${JSON.stringify(header_items_duplicate_flag)}`);
      if (!verified_security_token) {
        this.logwarn(
          `Disallowed header item ${this.cfg.duplicate_to_sender_flag_name}. This could be a plugin bug (most likely) or a malicious attempt.`
        );
        this.logdebug('DENYING email - duplicate flag present without verified security token');
        return next(DENY);
      }
      this.logdebug('Duplicate flag present and security token verified');
      if (header_items_duplicate_flag.length != 1) {
        this.logcrit(
          `Header item ${this.cfg.duplicate_to_sender_flag_name} should not appear more than once: ${header_items_duplicate_flag}`
        );
        this.logdebug('DENYING email - multiple duplicate flag headers found');
        return next(DENY, "Internal server error");
      }
    } else {
      this.logdebug('No duplicate flag header found');
    }

    this.logdebug('=== security_inspection completed successfully ===');
    return next();
  })();
}

exports.duplicate_to_sender = function (next, connection) {
  this.logdebug('=== duplicate_to_sender hook called ===');
  this.logdebug('Checking Redis availability');
  if (!this.ensure_redis()) {
    this.logcrit("Redis is not available!");
    return next(DENY, "Internal server error");
  }
  this.logdebug('Redis is available');

  const duplicate_flags = connection.transaction.header.get_all(this.cfg.duplicate_to_sender_flag_name);
  this.logdebug(`Checking for duplicate flag: ${this.cfg.duplicate_to_sender_flag_name}`);
  this.logdebug(`Found ${duplicate_flags.length} duplicate flag(s)`);
  if (duplicate_flags.length) {
    this.logdebug("Will not duplicate to sender a mail that is already a duplicate.");
    return next();
  }
  this.logdebug('Mail is not a duplicate, proceeding with duplication');

  // Currently we duplicate all outbound mails to sender.
  // This might not make sense if Haraka is working as a relay.
  const plugin = this;

  // Capture header data before async callback since connection may be null later
  const original_header_items = connection.transaction.header.lines();
  const email_shape = calculate_shape(connection.transaction.header);
  const from = connection.transaction.header.get('From');
  const to = connection.transaction.header.get('To');

  this.logdebug('Getting message stream data for duplication');
  this.logdebug(`Original header has ${original_header_items.length} lines`);
  this.logdebug(`Calculated email shape: ${email_shape}`);

  // Duplicate the outbound mail
  // and add headers to mark it as duplicated
  connection.transaction.message_stream.get_data(
    raw => {
      plugin.logdebug(`Raw message size: ${raw.length} bytes`);
      (async () => {
        const full_text = raw.toString("utf8");
        plugin.logdebug(`Full text length: ${full_text.length} characters`);
        const separator_index = full_text.search(/\r?\n\r?\n/);
        plugin.logdebug(`Header/body separator found at index: ${separator_index}`);
        const body_text = full_text.substring(separator_index).replace(/^\r?\n\r?\n/, '');
        plugin.logdebug(`Body text length: ${body_text.length} characters`);
        const token = crypto.randomBytes(32).toString('hex');
        plugin.logdebug(`Generated security token: ${token}`);
        const redis_key = `${plugin.cfg.redis_hash_name}:${token}`;
        plugin.logdebug(`Storing shape in Redis with key: ${redis_key} (expires in 60s)`);
        await server.notes.redis.set(redis_key, email_shape, { EX : 60 });
        // Create a copy of header_items to avoid modifying frozen array
        const header_items = original_header_items.slice();
        plugin.logdebug(`Adding header: ${plugin.cfg.duplicate_to_sender_flag_name}: ${plugin.cfg.duplicate_to_sender_flag_value}`);
        header_items.push(`${plugin.cfg.duplicate_to_sender_flag_name}: ${plugin.cfg.duplicate_to_sender_flag_value}`);
        plugin.logdebug(`Adding header: ${plugin.cfg.security_token_name}: ${token}`);
        header_items.push(`${plugin.cfg.security_token_name}: ${token}`);
        const duplicate_full_text = header_items.join('\r\n') + '\r\n\r\n' + body_text;
        plugin.logdebug(`Duplicate message length: ${duplicate_full_text.length} characters`);
        plugin.logdebug(`Sending duplicate email - From: ${from}, To: ${to}`);
        plugin.outbound.send_email(from, to, duplicate_full_text, (err) => {
          if (err) {
            plugin.logerror(`Failed to send duplicate email: ${err}`);
          } else {
            plugin.logdebug('Duplicate email sent to outbound queue');
          }
        });
      })();
    }
  );
  this.logdebug('=== duplicate_to_sender completed ===');
  return next();
}

exports.ensure_redis = function () {
  this.logdebug('Checking if server.notes.redis is available');
  if (!server.notes.redis) {
    this.logcrit("Redis is not available!");
    this.logdebug('server.notes.redis is null/undefined');
    return false;
  }
  this.logdebug('server.notes.redis is available');
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
  // Note: logdebug not available in standalone function
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
