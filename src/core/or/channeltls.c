/* * Copyright (c) 2012-2021, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file channeltls.c
 *
 * \brief A concrete subclass of channel_t using or_connection_t to transfer
 * cells between Tor instances.
 *
 * This module fills in the various function pointers in channel_t, to
 * implement the channel_tls_t channels as used in Tor today.  These channels
 * are created from channel_tls_connect() and
 * channel_tls_handle_incoming(). Each corresponds 1:1 to or_connection_t
 * object, as implemented in connection_or.c.  These channels transmit cells
 * to the underlying or_connection_t by calling
 * connection_or_write_*_cell_to_buf(), and receive cells from the underlying
 * or_connection_t when connection_or_process_cells_from_inbuf() calls
 * channel_tls_handle_*_cell().
 *
 * Here we also implement the server (responder) side of the v3+ Tor link
 * handshake, which uses CERTS and AUTHENTICATE cell to negotiate versions,
 * exchange expected and observed IP and time information, and bootstrap a
 * level of authentication higher than we have gotten on the raw TLS
 * handshake.
 *
 * NOTE: Since there is currently only one type of channel, there are probably
 * more than a few cases where functionality that is currently in
 * channeltls.c, connection_or.c, and channel.c ought to be divided up
 * differently.  The right time to do this is probably whenever we introduce
 * our next channel type.
 **/

/*
 * Define this so channel.h gives us things only channel_t subclasses
 * should touch.
 */
#include "core/or/circuitmux_ewfd.h"
#define CHANNEL_OBJECT_PRIVATE

#define CHANNELTLS_PRIVATE

#include "core/or/or.h"
#include "core/or/channel.h"
#include "core/or/channeltls.h"
#include "core/or/circuitmux.h"
#include "core/or/circuitmux_ewma.h"
#include "core/or/circuitmux_ewfd.h"
#include "core/or/command.h"
#include "app/config/config.h"
#include "app/config/resolve_addr.h"
#include "core/mainloop/connection.h"
#include "core/or/connection_or.h"
#include "feature/relay/relay_handshake.h"
#include "feature/control/control.h"
#include "feature/client/entrynodes.h"
#include "trunnel/link_handshake.h"
#include "core/or/relay.h"
#include "feature/stats/rephist.h"
#include "feature/relay/router.h"
#include "feature/relay/routermode.h"
#include "feature/nodelist/dirlist.h"
#include "core/or/scheduler.h"
#include "feature/nodelist/torcert.h"
#include "feature/nodelist/networkstatus.h"
#include "trunnel/channelpadding_negotiation.h"
#include "trunnel/netinfo.h"
#include "core/or/channelpadding.h"
#include "core/or/extendinfo.h"
#include "core/or/congestion_control_common.h"

#include "core/or/cell_st.h"
#include "core/or/cell_queue_st.h"
#include "core/or/or_connection_st.h"
#include "core/or/or_handshake_certs_st.h"
#include "core/or/or_handshake_state_st.h"
#include "feature/nodelist/routerinfo_st.h"
#include "core/or/var_cell_st.h"
#include "feature/relay/relay_find_addr.h"

#include "lib/tls/tortls.h"
#include "lib/tls/x509.h"

/** How many CELL_PADDING cells have we received, ever? */
uint64_t stats_n_padding_cells_processed = 0;
/** How many CELL_VERSIONS cells have we received, ever? */
uint64_t stats_n_versions_cells_processed = 0;
/** How many CELL_NETINFO cells have we received, ever? */
uint64_t stats_n_netinfo_cells_processed = 0;
/** How many CELL_VPADDING cells have we received, ever? */
uint64_t stats_n_vpadding_cells_processed = 0;
/** How many CELL_CERTS cells have we received, ever? */
uint64_t stats_n_certs_cells_processed = 0;
/** How many CELL_AUTH_CHALLENGE cells have we received, ever? */
uint64_t stats_n_auth_challenge_cells_processed = 0;
/** How many CELL_AUTHENTICATE cells have we received, ever? */
uint64_t stats_n_authenticate_cells_processed = 0;
/** How many CELL_AUTHORIZE cells have we received, ever? */
uint64_t stats_n_authorize_cells_processed = 0;

/** Active listener, if any */
static channel_listener_t *channel_tls_listener = NULL;

/* channel_tls_t method declarations */

static void channel_tls_close_method(channel_t *chan);
static const char * channel_tls_describe_transport_method(channel_t *chan);
static void channel_tls_free_method(channel_t *chan);
static double channel_tls_get_overhead_estimate_method(channel_t *chan);
static int channel_tls_get_remote_addr_method(const channel_t *chan,
                                              tor_addr_t *addr_out);
static int
channel_tls_get_transport_name_method(channel_t *chan, char **transport_out);
static const char *channel_tls_describe_peer_method(const channel_t *chan);
static int channel_tls_has_queued_writes_method(channel_t *chan);
static int channel_tls_is_canonical_method(channel_t *chan);
static int
channel_tls_matches_extend_info_method(channel_t *chan,
                                       extend_info_t *extend_info);
static int channel_tls_matches_target_method(channel_t *chan,
                                             const tor_addr_t *target);
static int channel_tls_num_cells_writeable_method(channel_t *chan);
static size_t channel_tls_num_bytes_queued_method(channel_t *chan);
static int channel_tls_write_cell_method(channel_t *chan,
                                         cell_t *cell);
static int channel_tls_write_packed_cell_method(channel_t *chan,
                                                packed_cell_t *packed_cell);
static int channel_tls_write_var_cell_method(channel_t *chan,
                                             var_cell_t *var_cell);

/* channel_listener_tls_t method declarations */

static void channel_tls_listener_close_method(channel_listener_t *chan_l);
static const char *
channel_tls_listener_describe_transport_method(channel_listener_t *chan_l);

/** Handle incoming cells for the handshake stuff here rather than
 * passing them on up. */

static void channel_tls_process_versions_cell(var_cell_t *cell,
                                              channel_tls_t *tlschan);
static void channel_tls_process_netinfo_cell(cell_t *cell,
                                             channel_tls_t *tlschan);
static int command_allowed_before_handshake(uint8_t command);
static int enter_v3_handshake_with_cell(var_cell_t *cell,
                                        channel_tls_t *tlschan);
static void channel_tls_process_padding_negotiate_cell(cell_t *cell,
                                                       channel_tls_t *chan);

/**
 * Do parts of channel_tls_t initialization common to channel_tls_connect()
 * and channel_tls_handle_incoming().
 */
STATIC void
channel_tls_common_init(channel_tls_t *tlschan)
{
  channel_t *chan;

  tor_assert(tlschan);

  chan = &(tlschan->base_);
  channel_init(chan);
  chan->magic = TLS_CHAN_MAGIC;
  chan->state = CHANNEL_STATE_OPENING;
  chan->close = channel_tls_close_method;
  chan->describe_transport = channel_tls_describe_transport_method;
  chan->free_fn = channel_tls_free_method;
  chan->get_overhead_estimate = channel_tls_get_overhead_estimate_method;
  chan->get_remote_addr = channel_tls_get_remote_addr_method;
  chan->describe_peer = channel_tls_describe_peer_method;
  chan->get_transport_name = channel_tls_get_transport_name_method;
  chan->has_queued_writes = channel_tls_has_queued_writes_method;
  chan->is_canonical = channel_tls_is_canonical_method;
  chan->matches_extend_info = channel_tls_matches_extend_info_method;
  chan->matches_target = channel_tls_matches_target_method;
  chan->num_bytes_queued = channel_tls_num_bytes_queued_method;
  chan->num_cells_writeable = channel_tls_num_cells_writeable_method;
  chan->write_cell = channel_tls_write_cell_method;
  chan->write_packed_cell = channel_tls_write_packed_cell_method;
  chan->write_var_cell = channel_tls_write_var_cell_method;

  chan->cmux = circuitmux_alloc();
  /* We only have one policy for now so always set it to EWMA. */
  // circuitmux_set_policy(chan->cmux, &ewma_policy);
  circuitmux_policy_t* current = ewfd_get_mux_policy();
  circuitmux_set_policy(chan->cmux, current);
}

/**
 * Start a new TLS channel.
 *
 * Launch a new OR connection to <b>addr</b>:<b>port</b> and expect to
 * handshake with an OR with identity digest <b>id_digest</b>, and wrap
 * it in a channel_tls_t.
 */
channel_t *
channel_tls_connect(const tor_addr_t *addr, uint16_t port,
                    const char *id_digest,
                    const ed25519_public_key_t *ed_id)
{
  channel_tls_t *tlschan = tor_malloc_zero(sizeof(*tlschan));
  channel_t *chan = &(tlschan->base_);

  channel_tls_common_init(tlschan);

  log_debug(LD_CHANNEL,
            "In channel_tls_connect() for channel %p "
            "(global id %"PRIu64 ")",
            tlschan,
            (chan->global_identifier));

  if (is_local_to_resolve_addr(addr)) {
    log_debug(LD_CHANNEL,
              "Marking new outgoing channel %"PRIu64 " at %p as local",
              (chan->global_identifier), chan);
    channel_mark_local(chan);
  } else {
    log_debug(LD_CHANNEL,
              "Marking new outgoing channel %"PRIu64 " at %p as remote",
              (chan->global_identifier), chan);
    channel_mark_remote(chan);
  }

  channel_mark_outgoing(chan);

  /* Set up or_connection stuff */
  tlschan->conn = connection_or_connect(addr, port, id_digest, ed_id, tlschan);
  /* connection_or_connect() will fill in tlschan->conn */
  if (!(tlschan->conn)) {
    chan->reason_for_closing = CHANNEL_CLOSE_FOR_ERROR;
    channel_change_state(chan, CHANNEL_STATE_ERROR);
    goto err;
  }

  log_debug(LD_CHANNEL,
            "Got orconn %p for channel with global id %"PRIu64,
            tlschan->conn, (chan->global_identifier));

  goto done;

 err:
  circuitmux_free(chan->cmux);
  tor_free(tlschan);
  chan = NULL;

 done:
  /* If we got one, we should register it */
  if (chan) channel_register(chan);

  return chan;
}

/**
 * Return the current channel_tls_t listener.
 *
 * Returns the current channel listener for incoming TLS connections, or
 * NULL if none has been established
 */
channel_listener_t *
channel_tls_get_listener(void)
{
  return channel_tls_listener;
}

/**
 * Start a channel_tls_t listener if necessary.
 *
 * Return the current channel_tls_t listener, or start one if we haven't yet,
 * and return that.
 */
channel_listener_t *
channel_tls_start_listener(void)
{
  channel_listener_t *listener;

  if (!channel_tls_listener) {
    listener = tor_malloc_zero(sizeof(*listener));
    channel_init_listener(listener);
    listener->state = CHANNEL_LISTENER_STATE_LISTENING;
    listener->close = channel_tls_listener_close_method;
    listener->describe_transport =
      channel_tls_listener_describe_transport_method;

    channel_tls_listener = listener;

    log_debug(LD_CHANNEL,
              "Starting TLS channel listener %p with global id %"PRIu64,
              listener, (listener->global_identifier));

    channel_listener_register(listener);
  } else listener = channel_tls_listener;

  return listener;
}

/**
 * Free everything on shutdown.
 *
 * Not much to do here, since channel_free_all() takes care of a lot, but let's
 * get rid of the listener.
 */
void
channel_tls_free_all(void)
{
  channel_listener_t *old_listener = NULL;

  log_debug(LD_CHANNEL,
            "Shutting down TLS channels...");

  if (channel_tls_listener) {
    /*
     * When we close it, channel_tls_listener will get nulled out, so save
     * a pointer so we can free it.
     */
    old_listener = channel_tls_listener;
    log_debug(LD_CHANNEL,
              "Closing channel_tls_listener with ID %"PRIu64
              " at %p.",
              (old_listener->global_identifier),
              old_listener);
    channel_listener_unregister(old_listener);
    channel_listener_mark_for_close(old_listener);
    channel_listener_free(old_listener);
    tor_assert(channel_tls_listener == NULL);
  }

  log_debug(LD_CHANNEL,
            "Done shutting down TLS channels");
}

/**
 * Create a new channel around an incoming or_connection_t.
 */
channel_t *
channel_tls_handle_incoming(or_connection_t *orconn)
{
  channel_tls_t *tlschan = tor_malloc_zero(sizeof(*tlschan));
  channel_t *chan = &(tlschan->base_);

  tor_assert(orconn);
  tor_assert(!(orconn->chan));

  channel_tls_common_init(tlschan);

  /* Link the channel and orconn to each other */
  tlschan->conn = orconn;
  orconn->chan = tlschan;

  if (is_local_to_resolve_addr(&(TO_CONN(orconn)->addr))) {
    log_debug(LD_CHANNEL,
              "Marking new incoming channel %"PRIu64 " at %p as local",
              (chan->global_identifier), chan);
    channel_mark_local(chan);
  } else {
    log_debug(LD_CHANNEL,
              "Marking new incoming channel %"PRIu64 " at %p as remote",
              (chan->global_identifier), chan);
    channel_mark_remote(chan);
  }

  channel_mark_incoming(chan);

  /* Register it */
  channel_register(chan);

  return chan;
}

/**
 * Set the `potentially_used_for_bootstrapping` flag on the or_connection_t
 * corresponding to the provided channel.
 *
 * This flag indicates that if the connection fails, it might be interesting
 * to the bootstrapping subsystem.  (The bootstrapping system only cares about
 * channels that we have tried to use for our own circuits.  Other channels
 * may have been launched in response to EXTEND cells from somebody else, and
 * if they fail, it won't necessarily indicate a bootstrapping problem.)
 **/
void
channel_mark_as_used_for_origin_circuit(channel_t *chan)
{
  if (BUG(!chan))
    return;
  if (chan->magic != TLS_CHAN_MAGIC)
    return;
  channel_tls_t *tlschan = channel_tls_from_base(chan);
  if (BUG(!tlschan))
    return;

  if (tlschan->conn)
    tlschan->conn->potentially_used_for_bootstrapping = 1;
}

/*********
 * Casts *
 ********/

/**
 * Cast a channel_tls_t to a channel_t.
 */
channel_t *
channel_tls_to_base(channel_tls_t *tlschan)
{
  if (!tlschan) return NULL;

  return &(tlschan->base_);
}

/**
 * Cast a channel_t to a channel_tls_t, with appropriate type-checking
 * asserts.
 */
channel_tls_t *
channel_tls_from_base(channel_t *chan)
{
  if (!chan) return NULL;

  tor_assert(chan->magic == TLS_CHAN_MAGIC);

  return (channel_tls_t *)(chan);
}

/**
 * Cast a const channel_tls_t to a const channel_t.
 */
const channel_t *
channel_tls_to_base_const(const channel_tls_t *tlschan)
{
  return channel_tls_to_base((channel_tls_t*) tlschan);
}

/**
 * Cast a const channel_t to a const channel_tls_t, with appropriate
 * type-checking asserts.
 */
const channel_tls_t *
channel_tls_from_base_const(const channel_t *chan)
{
  return channel_tls_from_base((channel_t *)chan);
}

/********************************************
 * Method implementations for channel_tls_t *
 *******************************************/

/**
 * Close a channel_tls_t.
 *
 * This implements the close method for channel_tls_t.
 */
static void
channel_tls_close_method(channel_t *chan)
{
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);

  tor_assert(tlschan);

  if (tlschan->conn) connection_or_close_normally(tlschan->conn, 1);
  else {
    /* Weird - we'll have to change the state ourselves, I guess */
    log_info(LD_CHANNEL,
             "Tried to close channel_tls_t %p with NULL conn",
             tlschan);
    channel_change_state(chan, CHANNEL_STATE_ERROR);
  }
}

/**
 * Describe the transport for a channel_tls_t.
 *
 * This returns the string "TLS channel on connection <id>" to the upper
 * layer.
 */
static const char *
channel_tls_describe_transport_method(channel_t *chan)
{
  static char *buf = NULL;
  uint64_t id;
  channel_tls_t *tlschan;
  const char *rv = NULL;

  tor_assert(chan);

  tlschan = BASE_CHAN_TO_TLS(chan);

  if (tlschan->conn) {
    id = TO_CONN(tlschan->conn)->global_identifier;

    if (buf) tor_free(buf);
    tor_asprintf(&buf,
                 "TLS channel (connection %"PRIu64 ")",
                 (id));

    rv = buf;
  } else {
    rv = "TLS channel (no connection)";
  }

  return rv;
}

/**
 * Free a channel_tls_t.
 *
 * This is called by the generic channel layer when freeing a channel_tls_t;
 * this happens either on a channel which has already reached
 * CHANNEL_STATE_CLOSED or CHANNEL_STATE_ERROR from channel_run_cleanup() or
 * on shutdown from channel_free_all().  In the latter case we might still
 * have an orconn active (which connection_free_all() will get to later),
 * so we should null out its channel pointer now.
 */
static void
channel_tls_free_method(channel_t *chan)
{
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);

  tor_assert(tlschan);

  if (tlschan->conn) {
    tlschan->conn->chan = NULL;
    tlschan->conn = NULL;
  }
}

/**
 * Get an estimate of the average TLS overhead for the upper layer.
 */
static double
channel_tls_get_overhead_estimate_method(channel_t *chan)
{
  double overhead = 1.0;
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);

  tor_assert(tlschan);
  tor_assert(tlschan->conn);

  /* Just return 1.0f if we don't have sensible data */
  if (tlschan->conn->bytes_xmitted > 0 &&
      tlschan->conn->bytes_xmitted_by_tls >=
      tlschan->conn->bytes_xmitted) {
    overhead = ((double)(tlschan->conn->bytes_xmitted_by_tls)) /
      ((double)(tlschan->conn->bytes_xmitted));

    /*
     * Never estimate more than 2.0; otherwise we get silly large estimates
     * at the very start of a new TLS connection.
     */
    if (overhead > 2.0)
      overhead = 2.0;
  }

  log_debug(LD_CHANNEL,
            "Estimated overhead ratio for TLS chan %"PRIu64 " is %f",
            (chan->global_identifier), overhead);

  return overhead;
}

/**
 * Get the remote address of a channel_tls_t.
 *
 * This implements the get_remote_addr method for channel_tls_t; copy the
 * remote endpoint of the channel to addr_out and return 1.  (Always
 * succeeds if this channel is attached to an OR connection.)
 *
 * Always returns the real address of the peer, not the canonical address.
 */
static int
channel_tls_get_remote_addr_method(const channel_t *chan,
                                   tor_addr_t *addr_out)
{
  const channel_tls_t *tlschan = CONST_BASE_CHAN_TO_TLS(chan);

  tor_assert(tlschan);
  tor_assert(addr_out);

  if (tlschan->conn == NULL) {
    tor_addr_make_unspec(addr_out);
    return 0;
  }

  /* They want the real address, so give it to them. */
  tor_addr_copy(addr_out, &TO_CONN(tlschan->conn)->addr);

  return 1;
}

/**
 * Get the name of the pluggable transport used by a channel_tls_t.
 *
 * This implements the get_transport_name for channel_tls_t. If the
 * channel uses a pluggable transport, copy its name to
 * <b>transport_out</b> and return 0. If the channel did not use a
 * pluggable transport, return -1.
 */
static int
channel_tls_get_transport_name_method(channel_t *chan, char **transport_out)
{
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);

  tor_assert(tlschan);
  tor_assert(transport_out);
  tor_assert(tlschan->conn);

  if (!tlschan->conn->ext_or_transport)
    return -1;

  *transport_out = tor_strdup(tlschan->conn->ext_or_transport);
  return 0;
}

/**
 * Get a human-readable endpoint description of a channel_tls_t.
 *
 * This format is intended for logging, and may change in the future;
 * nothing should parse or rely on its particular details.
 */
static const char *
channel_tls_describe_peer_method(const channel_t *chan)
{
  const channel_tls_t *tlschan = CONST_BASE_CHAN_TO_TLS(chan);
  tor_assert(tlschan);

  if (tlschan->conn) {
    return connection_describe_peer(TO_CONN(tlschan->conn));
  } else {
    return "(No connection)";
  }
}

/**
 * Tell the upper layer if we have queued writes.
 *
 * This implements the has_queued_writes method for channel_tls t_; it returns
 * 1 iff we have queued writes on the outbuf of the underlying or_connection_t.
 */
static int
channel_tls_has_queued_writes_method(channel_t *chan)
{
  size_t outbuf_len;
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);

  tor_assert(tlschan);
  if (!(tlschan->conn)) {
    log_info(LD_CHANNEL,
             "something called has_queued_writes on a tlschan "
             "(%p with ID %"PRIu64 " but no conn",
             chan, (chan->global_identifier));
  }

  outbuf_len = (tlschan->conn != NULL) ?
    connection_get_outbuf_len(TO_CONN(tlschan->conn)) :
    0;

  return (outbuf_len > 0);
}

/**
 * Tell the upper layer if we're canonical.
 *
 * This implements the is_canonical method for channel_tls_t:
 * it returns whether this is a canonical channel.
 */
static int
channel_tls_is_canonical_method(channel_t *chan)
{
  int answer = 0;
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);

  tor_assert(tlschan);

  if (tlschan->conn) {
    /* If this bit is set to 0, and link_proto is sufficiently old, then we
     * can't actually _rely_ on this being a non-canonical channel.
     * Nonetheless, we're going to believe that this is a non-canonical
     * channel in this case, since nobody should be using these link protocols
     * any more. */
    answer = tlschan->conn->is_canonical;
  }

  return answer;
}

/**
 * Check if we match an extend_info_t.
 *
 * This implements the matches_extend_info method for channel_tls_t; the upper
 * layer wants to know if this channel matches an extend_info_t.
 *
 * NOTE that this function only checks for an address/port match, and should
 * be used only when no identify is available.
 */
static int
channel_tls_matches_extend_info_method(channel_t *chan,
                                       extend_info_t *extend_info)
{
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);

  tor_assert(tlschan);
  tor_assert(extend_info);

  /* Never match if we have no conn */
  if (!(tlschan->conn)) {
    log_info(LD_CHANNEL,
             "something called matches_extend_info on a tlschan "
             "(%p with ID %"PRIu64 " but no conn",
             chan, (chan->global_identifier));
    return 0;
  }

  const tor_addr_port_t *orport = &tlschan->conn->canonical_orport;
  // If the canonical address is set, then we'll allow matches based on that.
  if (! tor_addr_is_unspec(&orport->addr)) {
    if (extend_info_has_orport(extend_info, &orport->addr, orport->port)) {
      return 1;
    }
  }

  // We also want to match if the true address and port are listed in the
  // extend info.
  return extend_info_has_orport(extend_info,
                                &TO_CONN(tlschan->conn)->addr,
                                TO_CONN(tlschan->conn)->port);
}

/**
 * Check if we match a target address; return true iff we do.
 *
 * This implements the matches_target method for channel_tls t_; the upper
 * layer wants to know if this channel matches a target address when extending
 * a circuit.
 */
static int
channel_tls_matches_target_method(channel_t *chan,
                                  const tor_addr_t *target)
{
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);

  tor_assert(tlschan);
  tor_assert(target);

  /* Never match if we have no conn */
  if (!(tlschan->conn)) {
    log_info(LD_CHANNEL,
             "something called matches_target on a tlschan "
             "(%p with ID %"PRIu64 " but no conn",
             chan, (chan->global_identifier));
    return 0;
  }

  /* addr is the address this connection came from.
   * canonical_orport is updated by connection_or_init_conn_from_address()
   * to be the address in the descriptor. It may be tempting to
   * allow either address to be allowed, but if we did so, it would
   * enable someone who steals a relay's keys to covertly impersonate/MITM it
   * from anywhere on the Internet! (Because they could make long-lived
   * TLS connections from anywhere to all relays, and wait for them to
   * be used for extends).
   *
   * An adversary who has stolen a relay's keys could also post a fake relay
   * descriptor, but that attack is easier to detect.
   */
  return tor_addr_eq(&TO_CONN(tlschan->conn)->addr, target);
}

/**
 * Tell the upper layer how many bytes we have queued and not yet
 * sent.
 */
static size_t
channel_tls_num_bytes_queued_method(channel_t *chan)
{
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);

  tor_assert(tlschan);
  tor_assert(tlschan->conn);

  return connection_get_outbuf_len(TO_CONN(tlschan->conn));
}

/**
 * Tell the upper layer how many cells we can accept to write.
 *
 * This implements the num_cells_writeable method for channel_tls_t; it
 * returns an estimate of the number of cells we can accept with
 * channel_tls_write_*_cell().
 */
static int
channel_tls_num_cells_writeable_method(channel_t *chan)
{
  size_t outbuf_len;
  ssize_t n;
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);
  size_t cell_network_size;

  tor_assert(tlschan);
  tor_assert(tlschan->conn);

  cell_network_size = get_cell_network_size(tlschan->conn->wide_circ_ids);
  outbuf_len = connection_get_outbuf_len(TO_CONN(tlschan->conn));
  /* Get the number of cells */
  n = CEIL_DIV(or_conn_highwatermark() - outbuf_len, cell_network_size);
  if (n < 0) n = 0;
#if SIZEOF_SIZE_T > SIZEOF_INT
  if (n > INT_MAX) n = INT_MAX;
#endif

  return (int)n;
}

/**
 * Write a cell to a channel_tls_t.
 *
 * This implements the write_cell method for channel_tls_t; given a
 * channel_tls_t and a cell_t, transmit the cell_t.
 */
static int
channel_tls_write_cell_method(channel_t *chan, cell_t *cell)
{
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);
  int written = 0;

  tor_assert(tlschan);
  tor_assert(cell);

  if (tlschan->conn) {
    connection_or_write_cell_to_buf(cell, tlschan->conn);
    ++written;
  } else {
    log_info(LD_CHANNEL,
             "something called write_cell on a tlschan "
             "(%p with ID %"PRIu64 " but no conn",
             chan, (chan->global_identifier));
  }

  return written;
}

/**
 * Write a packed cell to a channel_tls_t.
 *
 * This implements the write_packed_cell method for channel_tls_t; given a
 * channel_tls_t and a packed_cell_t, transmit the packed_cell_t.
 *
 * Return 0 on success or negative value on error. The caller must free the
 * packed cell.
 */
static int
channel_tls_write_packed_cell_method(channel_t *chan,
                                     packed_cell_t *packed_cell)
{
  tor_assert(chan);
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);
  size_t cell_network_size = get_cell_network_size(chan->wide_circ_ids);

  tor_assert(tlschan);
  tor_assert(packed_cell);

  if (tlschan->conn) {
    connection_buf_add(packed_cell->body, cell_network_size,
                            TO_CONN(tlschan->conn));
  } else {
    log_info(LD_CHANNEL,
             "something called write_packed_cell on a tlschan "
             "(%p with ID %"PRIu64 " but no conn",
             chan, (chan->global_identifier));
    return -1;
  }

  return 0;
}

/**
 * Write a variable-length cell to a channel_tls_t.
 *
 * This implements the write_var_cell method for channel_tls_t; given a
 * channel_tls_t and a var_cell_t, transmit the var_cell_t.
 */
static int
channel_tls_write_var_cell_method(channel_t *chan, var_cell_t *var_cell)
{
  channel_tls_t *tlschan = BASE_CHAN_TO_TLS(chan);
  int written = 0;

  tor_assert(tlschan);
  tor_assert(var_cell);

  if (tlschan->conn) {
    connection_or_write_var_cell_to_buf(var_cell, tlschan->conn);
    ++written;
  } else {
    log_info(LD_CHANNEL,
             "something called write_var_cell on a tlschan "
             "(%p with ID %"PRIu64 " but no conn",
             chan, (chan->global_identifier));
  }

  return written;
}

/*************************************************
 * Method implementations for channel_listener_t *
 ************************************************/

/**
 * Close a channel_listener_t.
 *
 * This implements the close method for channel_listener_t.
 */
static void
channel_tls_listener_close_method(channel_listener_t *chan_l)
{
  tor_assert(chan_l);

  /*
   * Listeners we just go ahead and change state through to CLOSED, but
   * make sure to check if they're channel_tls_listener to NULL it out.
   */
  if (chan_l == channel_tls_listener)
    channel_tls_listener = NULL;

  if (!(chan_l->state == CHANNEL_LISTENER_STATE_CLOSING ||
        chan_l->state == CHANNEL_LISTENER_STATE_CLOSED ||
        chan_l->state == CHANNEL_LISTENER_STATE_ERROR)) {
    channel_listener_change_state(chan_l, CHANNEL_LISTENER_STATE_CLOSING);
  }

  if (chan_l->incoming_list) {
    SMARTLIST_FOREACH_BEGIN(chan_l->incoming_list,
                            channel_t *, ichan) {
      channel_mark_for_close(ichan);
    } SMARTLIST_FOREACH_END(ichan);

    smartlist_free(chan_l->incoming_list);
    chan_l->incoming_list = NULL;
  }

  if (!(chan_l->state == CHANNEL_LISTENER_STATE_CLOSED ||
        chan_l->state == CHANNEL_LISTENER_STATE_ERROR)) {
    channel_listener_change_state(chan_l, CHANNEL_LISTENER_STATE_CLOSED);
  }
}

/**
 * Describe the transport for a channel_listener_t.
 *
 * This returns the string "TLS channel (listening)" to the upper
 * layer.
 */
static const char *
channel_tls_listener_describe_transport_method(channel_listener_t *chan_l)
{
  tor_assert(chan_l);

  return "TLS channel (listening)";
}

/*******************************************************
 * Functions for handling events on an or_connection_t *
 ******************************************************/

/**
 * Handle an orconn state change.
 *
 * This function will be called by connection_or.c when the or_connection_t
 * associated with this channel_tls_t changes state.
 */
void
channel_tls_handle_state_change_on_orconn(channel_tls_t *chan,
                                          or_connection_t *conn,
                                          uint8_t state)
{
  channel_t *base_chan;

  tor_assert(chan);
  tor_assert(conn);
  tor_assert(conn->chan == chan);
  tor_assert(chan->conn == conn);

  base_chan = TLS_CHAN_TO_BASE(chan);

  /* Make sure the base connection state makes sense - shouldn't be error
   * or closed. */

  tor_assert(CHANNEL_IS_OPENING(base_chan) ||
             CHANNEL_IS_OPEN(base_chan) ||
             CHANNEL_IS_MAINT(base_chan) ||
             CHANNEL_IS_CLOSING(base_chan));

  /* Did we just go to state open? */
  if (state == OR_CONN_STATE_OPEN) {
    /*
     * We can go to CHANNEL_STATE_OPEN from CHANNEL_STATE_OPENING or
     * CHANNEL_STATE_MAINT on this.
     */
    channel_change_state_open(base_chan);
    /* We might have just become writeable; check and tell the scheduler */
    if (connection_or_num_cells_writeable(conn) > 0) {
      scheduler_channel_wants_writes(base_chan);
    }
  } else {
    /*
     * Not open, so from CHANNEL_STATE_OPEN we go to CHANNEL_STATE_MAINT,
     * otherwise no change.
     */
    if (CHANNEL_IS_OPEN(base_chan)) {
      channel_change_state(base_chan, CHANNEL_STATE_MAINT);
    }
  }
}

#ifdef KEEP_TIMING_STATS

/**
 * Timing states wrapper.
 *
 * This is a wrapper function around the actual function that processes the
 * <b>cell</b> that just arrived on <b>chan</b>. Increment <b>*time</b>
 * by the number of microseconds used by the call to <b>*func(cell, chan)</b>.
 */
static void
channel_tls_time_process_cell(cell_t *cell, channel_tls_t *chan, int *time,
                              void (*func)(cell_t *, channel_tls_t *))
{
  struct timeval start, end;
  long time_passed;

  tor_gettimeofday(&start);

  (*func)(cell, chan);

  tor_gettimeofday(&end);
  time_passed = tv_udiff(&start, &end) ;

  if (time_passed > 10000) { /* more than 10ms */
    log_debug(LD_OR,"That call just took %ld ms.",time_passed/1000);
  }

  if (time_passed < 0) {
    log_info(LD_GENERAL,"That call took us back in time!");
    time_passed = 0;
  }

  *time += time_passed;
}
#endif /* defined(KEEP_TIMING_STATS) */

#ifdef KEEP_TIMING_STATS
#define PROCESS_CELL(tp, cl, cn) STMT_BEGIN {                   \
    ++num ## tp;                                                \
    channel_tls_time_process_cell(cl, cn, & tp ## time ,            \
                             channel_tls_process_ ## tp ## _cell);  \
    } STMT_END
#else /* !defined(KEEP_TIMING_STATS) */
#define PROCESS_CELL(tp, cl, cn) channel_tls_process_ ## tp ## _cell(cl, cn)
#endif /* defined(KEEP_TIMING_STATS) */

/**
 * Handle an incoming cell on a channel_tls_t.
 *
 * This is called from connection_or.c to handle an arriving cell; it checks
 * for cell types specific to the handshake for this transport protocol and
 * handles them, and queues all other cells to the channel_t layer, which
 * eventually will hand them off to command.c.
 *
 * The channel layer itself decides whether the cell should be queued or
 * can be handed off immediately to the upper-layer code.  It is responsible
 * for copying in the case that it queues; we merely pass pointers through
 * which we get from connection_or_process_cells_from_inbuf().
 */
void
channel_tls_handle_cell(cell_t *cell, or_connection_t *conn)
{
  channel_tls_t *chan;
  int handshaking;

  tor_assert(cell);
  tor_assert(conn);

  chan = conn->chan;

 if (!chan) {
   log_warn(LD_CHANNEL,
            "Got a cell_t on an OR connection with no channel");
   return;
  }

  handshaking = (TO_CONN(conn)->state != OR_CONN_STATE_OPEN);

  if (conn->base_.marked_for_close)
    return;

  /* Reject all but VERSIONS and NETINFO when handshaking. */
  /* (VERSIONS actually indicates a protocol warning: it's variable-length,
   * so if it reaches this function, we're on a v1 connection.) */
  if (handshaking && cell->command != CELL_VERSIONS &&
      cell->command != CELL_NETINFO) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Received unexpected cell command %d in chan state %s / "
           "conn state %s; closing the connection.",
           (int)cell->command,
           channel_state_to_string(TLS_CHAN_TO_BASE(chan)->state),
           conn_state_to_string(CONN_TYPE_OR, TO_CONN(conn)->state));
    connection_or_close_for_error(conn, 0);
    return;
  }

  if (conn->base_.state == OR_CONN_STATE_OR_HANDSHAKING_V3)
    or_handshake_state_record_cell(conn, conn->handshake_state, cell, 1);

  /* We note that we're on the internet whenever we read a cell. This is
   * a fast operation. */
  entry_guards_note_internet_connectivity(get_guard_selection_info());
  rep_hist_padding_count_read(PADDING_TYPE_TOTAL);

  if (TLS_CHAN_TO_BASE(chan)->padding_enabled)
    rep_hist_padding_count_read(PADDING_TYPE_ENABLED_TOTAL);

  switch (cell->command) {
    case CELL_PADDING:
      rep_hist_padding_count_read(PADDING_TYPE_CELL);
      if (TLS_CHAN_TO_BASE(chan)->padding_enabled)
        rep_hist_padding_count_read(PADDING_TYPE_ENABLED_CELL);
      ++stats_n_padding_cells_processed;
      /* do nothing */
      break;
    case CELL_VERSIONS:
      /* A VERSIONS cell should always be a variable-length cell, and
       * so should never reach this function (which handles constant-sized
       * cells). But if the connection is using the (obsolete) v1 link
       * protocol, all cells will be treated as constant-sized, and so
       * it's possible we'll reach this code.
       */
      log_fn(LOG_PROTOCOL_WARN, LD_CHANNEL,
             "Received unexpected VERSIONS cell on a channel using link "
             "protocol %d; ignoring.", conn->link_proto);
      break;
    case CELL_NETINFO:
      ++stats_n_netinfo_cells_processed;
      PROCESS_CELL(netinfo, cell, chan);
      break;
    case CELL_PADDING_NEGOTIATE:
      ++stats_n_netinfo_cells_processed;
      PROCESS_CELL(padding_negotiate, cell, chan);
      break;
    case CELL_CREATE:
    case CELL_CREATE_FAST:
    case CELL_CREATED:
    case CELL_CREATED_FAST:
    case CELL_RELAY:
    case CELL_RELAY_EARLY:
    case CELL_DESTROY:
    case CELL_CREATE2:
    case CELL_CREATED2:
      /*
       * These are all transport independent and we pass them up through the
       * channel_t mechanism.  They are ultimately handled in command.c.
       */
      channel_process_cell(TLS_CHAN_TO_BASE(chan), cell);
      break;
    default:
      log_fn(LOG_INFO, LD_PROTOCOL,
             "Cell of unknown type (%d) received in channeltls.c.  "
             "Dropping.",
             cell->command);
             break;
  }
}

/**
 * Handle an incoming variable-length cell on a channel_tls_t.
 *
 * Process a <b>var_cell</b> that was just received on <b>conn</b>. Keep
 * internal statistics about how many of each cell we've processed so far
 * this second, and the total number of microseconds it took to
 * process each type of cell.  All the var_cell commands are handshake-
 * related and live below the channel_t layer, so no variable-length
 * cells ever get delivered in the current implementation, but I've left
 * the mechanism in place for future use.
 *
 * If we were handing them off to the upper layer, the channel_t queueing
 * code would be responsible for memory management, and we'd just be passing
 * pointers through from connection_or_process_cells_from_inbuf().  That
 * caller always frees them after this function returns, so this function
 * should never free var_cell.
 */
void
channel_tls_handle_var_cell(var_cell_t *var_cell, or_connection_t *conn)
{
  channel_tls_t *chan;

#ifdef KEEP_TIMING_STATS
  /* how many of each cell have we seen so far this second? needs better
   * name. */
  static int num_versions = 0, num_certs = 0;
  static time_t current_second = 0; /* from previous calls to time */
  time_t now = time(NULL);

  if (current_second == 0) current_second = now;
  if (now > current_second) { /* the second has rolled over */
    /* print stats */
    log_info(LD_OR,
             "At end of second: %d versions (%d ms), %d certs (%d ms)",
             num_versions, versions_time / ((now - current_second) * 1000),
             num_certs, certs_time / ((now - current_second) * 1000));

    num_versions = num_certs = 0;
    versions_time = certs_time = 0;

    /* remember which second it is, for next time */
    current_second = now;
  }
#endif /* defined(KEEP_TIMING_STATS) */

  tor_assert(var_cell);
  tor_assert(conn);

  chan = conn->chan;

  if (!chan) {
    log_warn(LD_CHANNEL,
             "Got a var_cell_t on an OR connection with no channel");
    return;
  }

  if (TO_CONN(conn)->marked_for_close)
    return;

  switch (TO_CONN(conn)->state) {
    case OR_CONN_STATE_OR_HANDSHAKING_V2:
      if (var_cell->command != CELL_VERSIONS) {
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "Received a cell with command %d in unexpected "
               "orconn state \"%s\" [%d], channel state \"%s\" [%d]; "
               "closing the connection.",
               (int)(var_cell->command),
               conn_state_to_string(CONN_TYPE_OR, TO_CONN(conn)->state),
               TO_CONN(conn)->state,
               channel_state_to_string(TLS_CHAN_TO_BASE(chan)->state),
               (int)(TLS_CHAN_TO_BASE(chan)->state));
        /*
         * The code in connection_or.c will tell channel_t to close for
         * error; it will go to CHANNEL_STATE_CLOSING, and then to
         * CHANNEL_STATE_ERROR when conn is closed.
         */
        connection_or_close_for_error(conn, 0);
        return;
      }
      break;
    case OR_CONN_STATE_TLS_HANDSHAKING:
      /* If we're using bufferevents, it's entirely possible for us to
       * notice "hey, data arrived!" before we notice "hey, the handshake
       * finished!" And we need to be accepting both at once to handle both
       * the v2 and v3 handshakes. */
      /* But that should be happening any longer've disabled bufferevents. */
      tor_assert_nonfatal_unreached_once();
      FALLTHROUGH_UNLESS_ALL_BUGS_ARE_FATAL;
    case OR_CONN_STATE_TLS_SERVER_RENEGOTIATING:
      if (!(command_allowed_before_handshake(var_cell->command))) {
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "Received a cell with command %d in unexpected "
               "orconn state \"%s\" [%d], channel state \"%s\" [%d]; "
               "closing the connection.",
               (int)(var_cell->command),
               conn_state_to_string(CONN_TYPE_OR, TO_CONN(conn)->state),
               (int)(TO_CONN(conn)->state),
               channel_state_to_string(TLS_CHAN_TO_BASE(chan)->state),
               (int)(TLS_CHAN_TO_BASE(chan)->state));
        /* see above comment about CHANNEL_STATE_ERROR */
        connection_or_close_for_error(conn, 0);
        return;
      } else {
        if (enter_v3_handshake_with_cell(var_cell, chan) < 0)
          return;
      }
      break;
    case OR_CONN_STATE_OR_HANDSHAKING_V3:
      if (var_cell->command != CELL_AUTHENTICATE)
        or_handshake_state_record_var_cell(conn, conn->handshake_state,
                                           var_cell, 1);
      break; /* Everything is allowed */
    case OR_CONN_STATE_OPEN:
      if (conn->link_proto < 3) {
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "Received a variable-length cell with command %d in orconn "
               "state %s [%d], channel state %s [%d] with link protocol %d; "
               "ignoring it.",
               (int)(var_cell->command),
               conn_state_to_string(CONN_TYPE_OR, TO_CONN(conn)->state),
               (int)(TO_CONN(conn)->state),
               channel_state_to_string(TLS_CHAN_TO_BASE(chan)->state),
               (int)(TLS_CHAN_TO_BASE(chan)->state),
               (int)(conn->link_proto));
        return;
      }
      break;
    default:
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
             "Received var-length cell with command %d in unexpected "
             "orconn state \"%s\" [%d], channel state \"%s\" [%d]; "
             "ignoring it.",
             (int)(var_cell->command),
             conn_state_to_string(CONN_TYPE_OR, TO_CONN(conn)->state),
             (int)(TO_CONN(conn)->state),
             channel_state_to_string(TLS_CHAN_TO_BASE(chan)->state),
             (int)(TLS_CHAN_TO_BASE(chan)->state));
      return;
  }

  /* We note that we're on the internet whenever we read a cell. This is
   * a fast operation. */
  entry_guards_note_internet_connectivity(get_guard_selection_info());

  /* Now handle the cell */

  switch (var_cell->command) {
    case CELL_VERSIONS:
      ++stats_n_versions_cells_processed;
      PROCESS_CELL(versions, var_cell, chan);
      break;
    case CELL_VPADDING:
      ++stats_n_vpadding_cells_processed;
      /* Do nothing */
      break;
    case CELL_CERTS:
      ++stats_n_certs_cells_processed;
      PROCESS_CELL(certs, var_cell, chan);
      break;
    case CELL_AUTH_CHALLENGE:
      ++stats_n_auth_challenge_cells_processed;
      PROCESS_CELL(auth_challenge, var_cell, chan);
      break;
    case CELL_AUTHENTICATE:
      ++stats_n_authenticate_cells_processed;
      PROCESS_CELL(authenticate, var_cell, chan);
      break;
    case CELL_AUTHORIZE:
      ++stats_n_authorize_cells_processed;
      /* Ignored so far. */
      break;
    default:
      log_fn(LOG_INFO, LD_PROTOCOL,
             "Variable-length cell of unknown type (%d) received.",
             (int)(var_cell->command));
      break;
  }
}

#undef PROCESS_CELL

/**
 * Update channel marks after connection_or.c has changed an address.
 *
 * This is called from connection_or_init_conn_from_address() after the
 * connection's _base.addr or real_addr fields have potentially been changed
 * so we can recalculate the local mark.  Notably, this happens when incoming
 * connections are reverse-proxied and we only learn the real address of the
 * remote router by looking it up in the consensus after we finish the
 * handshake and know an authenticated identity digest.
 */
void
channel_tls_update_marks(or_connection_t *conn)
{
  channel_t *chan = NULL;

  tor_assert(conn);
  tor_assert(conn->chan);

  chan = TLS_CHAN_TO_BASE(conn->chan);

  if (is_local_to_resolve_addr(&(TO_CONN(conn)->addr))) {
    if (!channel_is_local(chan)) {
      log_debug(LD_CHANNEL,
                "Marking channel %"PRIu64 " at %p as local",
                (chan->global_identifier), chan);
      channel_mark_local(chan);
    }
  } else {
    if (channel_is_local(chan)) {
      log_debug(LD_CHANNEL,
                "Marking channel %"PRIu64 " at %p as remote",
                (chan->global_identifier), chan);
      channel_mark_remote(chan);
    }
  }
}

/**
 * Check if this cell type is allowed before the handshake is finished.
 *
 * Return true if <b>command</b> is a cell command that's allowed to start a
 * V3 handshake.
 */
static int
command_allowed_before_handshake(uint8_t command)
{
  switch (command) {
    case CELL_VERSIONS:
    case CELL_VPADDING:
    case CELL_AUTHORIZE:
      return 1;
    default:
      return 0;
  }
}

/**
 * Start a V3 handshake on an incoming connection.
 *
 * Called when we as a server receive an appropriate cell while waiting
 * either for a cell or a TLS handshake.  Set the connection's state to
 * "handshaking_v3', initializes the or_handshake_state field as needed,
 * and add the cell to the hash of incoming cells.)
 */
static int
enter_v3_handshake_with_cell(var_cell_t *cell, channel_tls_t *chan)
{
  int started_here = 0;

  tor_assert(cell);
  tor_assert(chan);
  tor_assert(chan->conn);

  started_here = connection_or_nonopen_was_started_here(chan->conn);

  tor_assert(TO_CONN(chan->conn)->state == OR_CONN_STATE_TLS_HANDSHAKING ||
             TO_CONN(chan->conn)->state ==
               OR_CONN_STATE_TLS_SERVER_RENEGOTIATING);

  if (started_here) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Received a cell while TLS-handshaking, not in "
           "OR_HANDSHAKING_V3, on a connection we originated.");
  }
  connection_or_block_renegotiation(chan->conn);
  connection_or_change_state(chan->conn, OR_CONN_STATE_OR_HANDSHAKING_V3);
  if (connection_init_or_handshake_state(chan->conn, started_here) < 0) {
    connection_or_close_for_error(chan->conn, 0);
    return -1;
  }
  or_handshake_state_record_var_cell(chan->conn,
                                     chan->conn->handshake_state, cell, 1);
  return 0;
}

/**
 * Process a 'versions' cell.
 *
 * This function is called to handle an incoming VERSIONS cell; the current
 * link protocol version must be 0 to indicate that no version has yet been
 * negotiated.  We compare the versions in the cell to the list of versions
 * we support, pick the highest version we have in common, and continue the
 * negotiation from there.
 */
static void
channel_tls_process_versions_cell(var_cell_t *cell, channel_tls_t *chan)
{
  int highest_supported_version = 0;
  int started_here = 0;

  tor_assert(cell);
  tor_assert(chan);
  tor_assert(chan->conn);

  if ((cell->payload_len % 2) == 1) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Received a VERSION cell with odd payload length %d; "
           "closing connection.",cell->payload_len);
    connection_or_close_for_error(chan->conn, 0);
    return;
  }

  started_here = connection_or_nonopen_was_started_here(chan->conn);

  if (chan->conn->link_proto != 0 ||
      (chan->conn->handshake_state &&
       chan->conn->handshake_state->received_versions)) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Received a VERSIONS cell on a connection with its version "
           "already set to %d; dropping",
           (int)(chan->conn->link_proto));
    return;
  }
  switch (chan->conn->base_.state)
    {
    case OR_CONN_STATE_OR_HANDSHAKING_V2:
    case OR_CONN_STATE_OR_HANDSHAKING_V3:
      break;
    case OR_CONN_STATE_TLS_HANDSHAKING:
    case OR_CONN_STATE_TLS_SERVER_RENEGOTIATING:
    default:
      log_fn(LOG_PROTOCOL_WARN, LD_OR,
             "VERSIONS cell while in unexpected state");
      return;
  }

  tor_assert(chan->conn->handshake_state);

  {
    int i;
    const uint8_t *cp = cell->payload;
    for (i = 0; i < cell->payload_len / 2; ++i, cp += 2) {
      uint16_t v = ntohs(get_uint16(cp));
      if (is_or_protocol_version_known(v) && v > highest_supported_version)
        highest_supported_version = v;
    }
  }
  if (!highest_supported_version) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Couldn't find a version in common between my version list and the "
           "list in the VERSIONS cell; closing connection.");
    connection_or_close_for_error(chan->conn, 0);
    return;
  } else if (highest_supported_version == 1) {
    /* Negotiating version 1 makes no sense, since version 1 has no VERSIONS
     * cells. */
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Used version negotiation protocol to negotiate a v1 connection. "
           "That's crazily non-compliant. Closing connection.");
    connection_or_close_for_error(chan->conn, 0);
    return;
  } else if (highest_supported_version < 3 &&
             chan->conn->base_.state == OR_CONN_STATE_OR_HANDSHAKING_V3) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Negotiated link protocol 2 or lower after doing a v3 TLS "
           "handshake. Closing connection.");
    connection_or_close_for_error(chan->conn, 0);
    return;
  } else if (highest_supported_version != 2 &&
             chan->conn->base_.state == OR_CONN_STATE_OR_HANDSHAKING_V2) {
    /* XXXX This should eventually be a log_protocol_warn */
    log_fn(LOG_WARN, LD_OR,
           "Negotiated link with non-2 protocol after doing a v2 TLS "
           "handshake with %s. Closing connection.",
           connection_describe_peer(TO_CONN(chan->conn)));
    connection_or_close_for_error(chan->conn, 0);
    return;
  }

  rep_hist_note_negotiated_link_proto(highest_supported_version, started_here);

  chan->conn->link_proto = highest_supported_version;
  chan->conn->handshake_state->received_versions = 1;

  if (chan->conn->link_proto == 2) {
    log_info(LD_OR,
             "Negotiated version %d on %s; sending NETINFO.",
             highest_supported_version,
             connection_describe(TO_CONN(chan->conn)));

    if (connection_or_send_netinfo(chan->conn) < 0) {
      connection_or_close_for_error(chan->conn, 0);
      return;
    }
  } else {
    const int send_versions = !started_here;
    /* If we want to authenticate, send a CERTS cell */
    const int send_certs = !started_here || public_server_mode(get_options());
    /* If we're a host that got a connection, ask for authentication. */
    const int send_chall = !started_here;
    /* If our certs cell will authenticate us, we can send a netinfo cell
     * right now. */
    const int send_netinfo = !started_here;
    const int send_any =
      send_versions || send_certs || send_chall || send_netinfo;
    tor_assert(chan->conn->link_proto >= 3);

    log_info(LD_OR,
             "Negotiated version %d with on %s; %s%s%s%s%s",
             highest_supported_version,
             connection_describe(TO_CONN(chan->conn)),
             send_any ? "Sending cells:" : "Waiting for CERTS cell",
             send_versions ? " VERSIONS" : "",
             send_certs ? " CERTS" : "",
             send_chall ? " AUTH_CHALLENGE" : "",
             send_netinfo ? " NETINFO" : "");

#ifdef DISABLE_V3_LINKPROTO_SERVERSIDE
    if (1) {
      connection_or_close_normally(chan->conn, 1);
      return;
    }
#endif /* defined(DISABLE_V3_LINKPROTO_SERVERSIDE) */

    if (send_versions) {
      if (connection_or_send_versions(chan->conn, 1) < 0) {
        log_warn(LD_OR, "Couldn't send versions cell");
        connection_or_close_for_error(chan->conn, 0);
        return;
      }
    }

    /* We set this after sending the versions cell. */
    /*XXXXX symbolic const.*/
    TLS_CHAN_TO_BASE(chan)->wide_circ_ids =
      chan->conn->link_proto >= MIN_LINK_PROTO_FOR_WIDE_CIRC_IDS;
    chan->conn->wide_circ_ids = TLS_CHAN_TO_BASE(chan)->wide_circ_ids;

    TLS_CHAN_TO_BASE(chan)->padding_enabled =
      chan->conn->link_proto >= MIN_LINK_PROTO_FOR_CHANNEL_PADDING;

    if (send_certs) {
      if (connection_or_send_certs_cell(chan->conn) < 0) {
        log_warn(LD_OR, "Couldn't send certs cell");
        connection_or_close_for_error(chan->conn, 0);
        return;
      }
    }
    if (send_chall) {
      if (connection_or_send_auth_challenge_cell(chan->conn) < 0) {
        log_warn(LD_OR, "Couldn't send auth_challenge cell");
        connection_or_close_for_error(chan->conn, 0);
        return;
      }
    }
    if (send_netinfo) {
      if (connection_or_send_netinfo(chan->conn) < 0) {
        log_warn(LD_OR, "Couldn't send netinfo cell");
        connection_or_close_for_error(chan->conn, 0);
        return;
      }
    }
  }
}

/**
 * Process a 'padding_negotiate' cell.
 *
 * This function is called to handle an incoming PADDING_NEGOTIATE cell;
 * enable or disable padding accordingly, and read and act on its timeout
 * value contents.
 */
static void
channel_tls_process_padding_negotiate_cell(cell_t *cell, channel_tls_t *chan)
{
  channelpadding_negotiate_t *negotiation;
  tor_assert(cell);
  tor_assert(chan);
  tor_assert(chan->conn);

  if (chan->conn->link_proto < MIN_LINK_PROTO_FOR_CHANNEL_PADDING) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Received a PADDING_NEGOTIATE cell on v%d connection; dropping.",
           chan->conn->link_proto);
    return;
  }

  if (channelpadding_negotiate_parse(&negotiation, cell->payload,
                                     CELL_PAYLOAD_SIZE) < 0) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
          "Received malformed PADDING_NEGOTIATE cell on v%d connection; "
          "dropping.", chan->conn->link_proto);

    return;
  }

  channelpadding_update_padding_for_channel(TLS_CHAN_TO_BASE(chan),
                                            negotiation);

  channelpadding_negotiate_free(negotiation);
}

/**
 * Convert <b>netinfo_addr</b> into corresponding <b>tor_addr</b>.
 * Return 0 on success; on failure, return -1 and log a warning.
 */
static int
tor_addr_from_netinfo_addr(tor_addr_t *tor_addr,
                           const netinfo_addr_t *netinfo_addr) {
  tor_assert(tor_addr);
  tor_assert(netinfo_addr);

  uint8_t type = netinfo_addr_get_addr_type(netinfo_addr);
  uint8_t len = netinfo_addr_get_len(netinfo_addr);

  if (type == NETINFO_ADDR_TYPE_IPV4 && len == 4)  {
    uint32_t ipv4 = netinfo_addr_get_addr_ipv4(netinfo_addr);
    tor_addr_from_ipv4h(tor_addr, ipv4);
  } else if (type == NETINFO_ADDR_TYPE_IPV6 && len == 16) {
    const uint8_t *ipv6_bytes = netinfo_addr_getconstarray_addr_ipv6(
                                  netinfo_addr);
    tor_addr_from_ipv6_bytes(tor_addr, ipv6_bytes);
  } else {
    log_fn(LOG_PROTOCOL_WARN, LD_OR, "Cannot read address from NETINFO "
                                     "- wrong type/length.");
    return -1;
  }

  return 0;
}

/**
 * Helper: compute the absolute value of a time_t.
 *
 * (we need this because labs() doesn't always work for time_t, since
 * long can be shorter than time_t.)
 */
static inline time_t
time_abs(time_t val)
{
  return (val < 0) ? -val : val;
}

/** Return true iff the channel can process a NETINFO cell. For this to return
 * true, these channel conditions apply:
 *
 *    1. Link protocol is version 2 or higher (tor-spec.txt, NETINFO cells
 *       section).
 *
 *    2. Underlying OR connection of the channel is either in v2 or v3
 *       handshaking state.
 */
static bool
can_process_netinfo_cell(const channel_tls_t *chan)
{
  /* NETINFO cells can only be negotiated on link protocol 2 or higher. */
  if (chan->conn->link_proto < 2) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Received a NETINFO cell on %s connection; dropping.",
           chan->conn->link_proto == 0 ? "non-versioned" : "a v1");
    return false;
  }

  /* Can't process a NETINFO cell if the connection is not handshaking. */
  if (chan->conn->base_.state != OR_CONN_STATE_OR_HANDSHAKING_V2 &&
      chan->conn->base_.state != OR_CONN_STATE_OR_HANDSHAKING_V3) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Received a NETINFO cell on non-handshaking connection; dropping.");
    return false;
  }

  /* Make sure we do have handshake state. */
  tor_assert(chan->conn->handshake_state);
  tor_assert(chan->conn->handshake_state->received_versions);

  return true;
}

/** Mark the given channel endpoint as a client (which means either a tor
 * client or a tor bridge).
 *
 * This MUST be done on an _unauthenticated_ channel. It is a mistake to mark
 * an authenticated channel as a client.
 *
 * The following is done on the channel:
 *
 *    1. Marked as a client.
 *    2. Type of circuit ID type is set.
 *    3. The underlying OR connection is initialized with the address of the
 *       endpoint.
 */
static void
mark_channel_tls_endpoint_as_client(channel_tls_t *chan)
{
  /* Ending up here for an authenticated link is a mistake. */
  if (BUG(chan->conn->handshake_state->authenticated)) {
    return;
  }

  tor_assert(tor_digest_is_zero(
            (const char*)(chan->conn->handshake_state->
                authenticated_rsa_peer_id)));
  tor_assert(fast_mem_is_zero(
            (const char*)(chan->conn->handshake_state->
                          authenticated_ed25519_peer_id.pubkey), 32));
  /* If the client never authenticated, it's a tor client or bridge
   * relay, and we must not use it for EXTEND requests (nor could we, as
   * there are no authenticated peer IDs) */
  channel_mark_client(TLS_CHAN_TO_BASE(chan));
  channel_set_circid_type(TLS_CHAN_TO_BASE(chan), NULL,
         chan->conn->link_proto < MIN_LINK_PROTO_FOR_WIDE_CIRC_IDS);

  connection_or_init_conn_from_address(chan->conn,
            &(chan->conn->base_.addr),
            chan->conn->base_.port,
            /* zero, checked above */
            (const char*)(chan->conn->handshake_state->
                          authenticated_rsa_peer_id),
            NULL, /* Ed25519 ID: Also checked as zero */
            0);
}

/**
 * Process a 'netinfo' cell
 *
 * This function is called to handle an incoming NETINFO cell; read and act
 * on its contents, and set the connection state to "open".
 */
static void
channel_tls_process_netinfo_cell(cell_t *cell, channel_tls_t *chan)
{
  time_t timestamp;
  uint8_t my_addr_type;
  uint8_t my_addr_len;
  uint8_t n_other_addrs;
  time_t now = time(NULL);
  const routerinfo_t *me = router_get_my_routerinfo();

  time_t apparent_skew = 0;
  tor_addr_t my_apparent_addr = TOR_ADDR_NULL;
  int started_here = 0;
  const char *identity_digest = NULL;

  tor_assert(cell);
  tor_assert(chan);
  tor_assert(chan->conn);

  /* Make sure we can process a NETINFO cell. Link protocol and state
   * validation is done to make sure of it. */
  if (!can_process_netinfo_cell(chan)) {
    return;
  }

  started_here = connection_or_nonopen_was_started_here(chan->conn);
  identity_digest = chan->conn->identity_digest;

  if (chan->conn->base_.state == OR_CONN_STATE_OR_HANDSHAKING_V3) {
    tor_assert(chan->conn->link_proto >= 3);
    if (started_here) {
      if (!(chan->conn->handshake_state->authenticated)) {
        log_fn(LOG_PROTOCOL_WARN, LD_OR,
               "Got a NETINFO cell from server, "
               "but no authentication.  Closing the connection.");
        connection_or_close_for_error(chan->conn, 0);
        return;
      }
    } else {
      /* We're the server. If the client never authenticated, we have some
       * housekeeping to do.
       *
       * It's a tor client or bridge relay, and we must not use it for EXTEND
       * requests (nor could we, as there are no authenticated peer IDs) */
      if (!(chan->conn->handshake_state->authenticated)) {
        mark_channel_tls_endpoint_as_client(chan);
      }
    }
  }

  /* Decode the cell. */
  netinfo_cell_t *netinfo_cell = NULL;

  ssize_t parsed = netinfo_cell_parse(&netinfo_cell, cell->payload,
                                      CELL_PAYLOAD_SIZE);

  if (parsed < 0) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Failed to parse NETINFO cell - closing connection.");
    connection_or_close_for_error(chan->conn, 0);
    return;
  }

  timestamp = netinfo_cell_get_timestamp(netinfo_cell);

  const netinfo_addr_t *my_addr =
    netinfo_cell_getconst_other_addr(netinfo_cell);

  my_addr_type = netinfo_addr_get_addr_type(my_addr);
  my_addr_len = netinfo_addr_get_len(my_addr);

  if ((now - chan->conn->handshake_state->sent_versions_at) < 180) {
    apparent_skew = now - timestamp;
  }
  /* We used to check:
   *    if (my_addr_len >= CELL_PAYLOAD_SIZE - 6) {
   *
   * This is actually never going to happen, since my_addr_len is at most 255,
   * and CELL_PAYLOAD_LEN - 6 is 503.  So we know that cp is < end. */

  if (tor_addr_from_netinfo_addr(&my_apparent_addr, my_addr) == -1) {
    connection_or_close_for_error(chan->conn, 0);
    netinfo_cell_free(netinfo_cell);
    return;
  }

  if (my_addr_type == NETINFO_ADDR_TYPE_IPV4 && my_addr_len == 4) {
    if (!get_options()->BridgeRelay && me &&
        tor_addr_eq(&my_apparent_addr, &me->ipv4_addr)) {
      TLS_CHAN_TO_BASE(chan)->is_canonical_to_peer = 1;
    }
  } else if (my_addr_type == NETINFO_ADDR_TYPE_IPV6 &&
             my_addr_len == 16) {
    if (!get_options()->BridgeRelay && me &&
        !tor_addr_is_null(&me->ipv6_addr) &&
        tor_addr_eq(&my_apparent_addr, &me->ipv6_addr)) {
      TLS_CHAN_TO_BASE(chan)->is_canonical_to_peer = 1;
    }
  }

  if (me) {
    /* We have a descriptor, so we are a relay: record the address that the
     * other side said we had. */
    tor_addr_copy(&TLS_CHAN_TO_BASE(chan)->addr_according_to_peer,
                  &my_apparent_addr);
  }

  n_other_addrs = netinfo_cell_get_n_my_addrs(netinfo_cell);
  for (uint8_t i = 0; i < n_other_addrs; i++) {
    /* Consider all the other addresses; if any matches, this connection is
     * "canonical." */

    const netinfo_addr_t *netinfo_addr =
      netinfo_cell_getconst_my_addrs(netinfo_cell, i);

    tor_addr_t addr;

    if (tor_addr_from_netinfo_addr(&addr, netinfo_addr) == -1) {
      log_fn(LOG_PROTOCOL_WARN,  LD_OR,
             "Bad address in netinfo cell; Skipping.");
      continue;
    }
    /* A relay can connect from anywhere and be canonical, so
     * long as it tells you from where it came. This may sound a bit
     * concerning... but that's what "canonical" means: that the
     * address is one that the relay itself has claimed.  The relay
     * might be doing something funny, but nobody else is doing a MITM
     * on the relay's TCP.
     */
    if (tor_addr_eq(&addr, &TO_CONN(chan->conn)->addr)) {
      connection_or_set_canonical(chan->conn, 1);
      break;
    }
  }

  netinfo_cell_free(netinfo_cell);

  if (me && !TLS_CHAN_TO_BASE(chan)->is_canonical_to_peer &&
      channel_is_canonical(TLS_CHAN_TO_BASE(chan))) {
    const char *descr = channel_describe_peer(
                                                    TLS_CHAN_TO_BASE(chan));
    log_info(LD_OR,
             "We made a connection to a relay at %s (fp=%s) but we think "
             "they will not consider this connection canonical. They "
             "think we are at %s, but we think its %s.",
             safe_str(descr),
             safe_str(hex_str(identity_digest, DIGEST_LEN)),
             safe_str(tor_addr_is_null(&my_apparent_addr) ?
             "<none>" : fmt_and_decorate_addr(&my_apparent_addr)),
             safe_str(fmt_addr(&me->ipv4_addr)));
  }

  /* Act on apparent skew. */
  /** Warn when we get a netinfo skew with at least this value. */
#define NETINFO_NOTICE_SKEW 3600
  if (time_abs(apparent_skew) > NETINFO_NOTICE_SKEW &&
      (started_here ||
       connection_or_digest_is_known_relay(chan->conn->identity_digest))) {
    int trusted = router_digest_is_trusted_dir(chan->conn->identity_digest);
    clock_skew_warning(TO_CONN(chan->conn), apparent_skew, trusted, LD_GENERAL,
                       "NETINFO cell", "OR");
  }

  /* Consider our apparent address as a possible suggestion for our address if
   * we were unable to resolve it previously. The endpoint address is passed
   * in order to make sure to never consider an address that is the same as
   * our endpoint. */
  relay_address_new_suggestion(&my_apparent_addr, &TO_CONN(chan->conn)->addr,
                               identity_digest);

  if (! chan->conn->handshake_state->sent_netinfo) {
    /* If we were prepared to authenticate, but we never got an AUTH_CHALLENGE
     * cell, then we would not previously have sent a NETINFO cell. Do so
     * now. */
    if (connection_or_send_netinfo(chan->conn) < 0) {
      connection_or_close_for_error(chan->conn, 0);
      return;
    }
  }

  if (connection_or_set_state_open(chan->conn) < 0) {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Got good NETINFO cell on %s; but "
           "was unable to make the OR connection become open.",
           connection_describe(TO_CONN(chan->conn)));
    connection_or_close_for_error(chan->conn, 0);
  } else {
    log_info(LD_OR,
             "Got good NETINFO cell on %s; OR connection is now "
             "open, using protocol version %d. Its ID digest is %s. "
             "Our address is apparently %s.",
             connection_describe(TO_CONN(chan->conn)),
             (int)(chan->conn->link_proto),
             hex_str(identity_digest, DIGEST_LEN),
             tor_addr_is_null(&my_apparent_addr) ?
               "<none>" :
               safe_str_client(fmt_and_decorate_addr(&my_apparent_addr)));
  }
  assert_connection_ok(TO_CONN(chan->conn),time(NULL));
}

/** Types of certificates that we know how to parse from CERTS cells.  Each
 * type corresponds to a different encoding format. */
typedef enum cert_encoding_t {
  CERT_ENCODING_UNKNOWN, /**< We don't recognize this. */
  CERT_ENCODING_X509, /**< It's an RSA key, signed with RSA, encoded in x509.
                   * (Actually, it might not be RSA. We test that later.) */
  CERT_ENCODING_ED25519, /**< It's something signed with an Ed25519 key,
                      * encoded asa a tor_cert_t.*/
  CERT_ENCODING_RSA_CROSSCERT, /**< It's an Ed key signed with an RSA key. */
} cert_encoding_t;

/**
 * Given one of the certificate type codes used in a CERTS cell,
 * return the corresponding cert_encoding_t that we should use to parse
 * the certificate.
 */
static cert_encoding_t
certs_cell_typenum_to_cert_type(int typenum)
{
  switch (typenum) {
  case CERTTYPE_RSA1024_ID_LINK:
  case CERTTYPE_RSA1024_ID_ID:
  case CERTTYPE_RSA1024_ID_AUTH:
    return CERT_ENCODING_X509;
  case CERTTYPE_ED_ID_SIGN:
  case CERTTYPE_ED_SIGN_LINK:
  case CERTTYPE_ED_SIGN_AUTH:
    return CERT_ENCODING_ED25519;
  case CERTTYPE_RSA1024_ID_EDID:
    return CERT_ENCODING_RSA_CROSSCERT;
  default:
    return CERT_ENCODING_UNKNOWN;
  }
}

/**
 * Process a CERTS cell from a channel.
 *
 * This function is called to process an incoming CERTS cell on a
 * channel_tls_t:
 *
 * If the other side should not have sent us a CERTS cell, or the cell is
 * malformed, or it is supposed to authenticate the TLS key but it doesn't,
 * then mark the connection.
 *
 * If the cell has a good cert chain and we're doing a v3 handshake, then
 * store the certificates in or_handshake_state.  If this is the client side
 * of the connection, we then authenticate the server or mark the connection.
 * If it's the server side, wait for an AUTHENTICATE cell.
 */
STATIC void
channel_tls_process_certs_cell(var_cell_t *cell, channel_tls_t *chan)
{
#define MAX_CERT_TYPE_WANTED CERTTYPE_RSA1024_ID_EDID
  /* These arrays will be sparse, since a cert type can be at most one
   * of ed/x509 */
  tor_x509_cert_t *x509_certs[MAX_CERT_TYPE_WANTED + 1];
  tor_cert_t *ed_certs[MAX_CERT_TYPE_WANTED + 1];
  uint8_t *rsa_ed_cc_cert = NULL;
  size_t rsa_ed_cc_cert_len = 0;

  int n_certs, i;
  certs_cell_t *cc = NULL;

  int send_netinfo = 0, started_here = 0;

  memset(x509_certs, 0, sizeof(x509_certs));
  memset(ed_certs, 0, sizeof(ed_certs));
  tor_assert(cell);
  tor_assert(chan);
  tor_assert(chan->conn);

#define ERR(s)                                                  \
  do {                                                          \
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,                      \
           "Received a bad CERTS cell on %s: %s",               \
           connection_describe(TO_CONN(chan->conn)),            \
           (s));                                                \
    connection_or_close_for_error(chan->conn, 0);               \
    goto err;                                                   \
  } while (0)

  /* Can't use connection_or_nonopen_was_started_here(); its conn->tls
   * check looks like it breaks
   * test_link_handshake_recv_certs_ok_server().  */
  started_here = chan->conn->handshake_state->started_here;

  if (chan->conn->base_.state != OR_CONN_STATE_OR_HANDSHAKING_V3)
    ERR("We're not doing a v3 handshake!");
  if (chan->conn->link_proto < 3)
    ERR("We're not using link protocol >= 3");
  if (chan->conn->handshake_state->received_certs_cell)
    ERR("We already got one");
  if (chan->conn->handshake_state->authenticated) {
    /* Should be unreachable, but let's make sure. */
    ERR("We're already authenticated!");
  }
  if (cell->payload_len < 1)
    ERR("It had no body");
  if (cell->circ_id)
    ERR("It had a nonzero circuit ID");

  if (certs_cell_parse(&cc, cell->payload, cell->payload_len) < 0)
    ERR("It couldn't be parsed.");

  n_certs = cc->n_certs;

  for (i = 0; i < n_certs; ++i) {
    certs_cell_cert_t *c = certs_cell_get_certs(cc, i);

    uint16_t cert_type = c->cert_type;
    uint16_t cert_len = c->cert_len;
    uint8_t *cert_body = certs_cell_cert_getarray_body(c);

    if (cert_type > MAX_CERT_TYPE_WANTED)
      continue;
    const cert_encoding_t ct = certs_cell_typenum_to_cert_type(cert_type);
    switch (ct) {
      default:
      case CERT_ENCODING_UNKNOWN:
        break;
      case CERT_ENCODING_X509: {
        tor_x509_cert_t *x509_cert = tor_x509_cert_decode(cert_body, cert_len);
        if (!x509_cert) {
          log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
                 "Received undecodable certificate in CERTS cell on %s",
                 connection_describe(TO_CONN(chan->conn)));
        } else {
          if (x509_certs[cert_type]) {
            tor_x509_cert_free(x509_cert);
            ERR("Duplicate x509 certificate");
          } else {
            x509_certs[cert_type] = x509_cert;
          }
        }
        break;
      }
      case CERT_ENCODING_ED25519: {
        tor_cert_t *ed_cert = tor_cert_parse(cert_body, cert_len);
        if (!ed_cert) {
          log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
                 "Received undecodable Ed certificate "
                 "in CERTS cell on %s",
                 connection_describe(TO_CONN(chan->conn)));
        } else {
          if (ed_certs[cert_type]) {
            tor_cert_free(ed_cert);
            ERR("Duplicate Ed25519 certificate");
          } else {
            ed_certs[cert_type] = ed_cert;
          }
        }
        break;
      }

     case CERT_ENCODING_RSA_CROSSCERT: {
        if (rsa_ed_cc_cert) {
          ERR("Duplicate RSA->Ed25519 crosscert");
        } else {
          rsa_ed_cc_cert = tor_memdup(cert_body, cert_len);
          rsa_ed_cc_cert_len = cert_len;
        }
        break;
      }
    }
  }

  /* Move the certificates we (might) want into the handshake_state->certs
   * structure. */
  tor_x509_cert_t *id_cert = x509_certs[CERTTYPE_RSA1024_ID_ID];
  tor_x509_cert_t *auth_cert = x509_certs[CERTTYPE_RSA1024_ID_AUTH];
  tor_x509_cert_t *link_cert = x509_certs[CERTTYPE_RSA1024_ID_LINK];
  chan->conn->handshake_state->certs->auth_cert = auth_cert;
  chan->conn->handshake_state->certs->link_cert = link_cert;
  chan->conn->handshake_state->certs->id_cert = id_cert;
  x509_certs[CERTTYPE_RSA1024_ID_ID] =
    x509_certs[CERTTYPE_RSA1024_ID_AUTH] =
    x509_certs[CERTTYPE_RSA1024_ID_LINK] = NULL;

  tor_cert_t *ed_id_sign = ed_certs[CERTTYPE_ED_ID_SIGN];
  tor_cert_t *ed_sign_link = ed_certs[CERTTYPE_ED_SIGN_LINK];
  tor_cert_t *ed_sign_auth = ed_certs[CERTTYPE_ED_SIGN_AUTH];
  chan->conn->handshake_state->certs->ed_id_sign = ed_id_sign;
  chan->conn->handshake_state->certs->ed_sign_link = ed_sign_link;
  chan->conn->handshake_state->certs->ed_sign_auth = ed_sign_auth;
  ed_certs[CERTTYPE_ED_ID_SIGN] =
    ed_certs[CERTTYPE_ED_SIGN_LINK] =
    ed_certs[CERTTYPE_ED_SIGN_AUTH] = NULL;

  chan->conn->handshake_state->certs->ed_rsa_crosscert = rsa_ed_cc_cert;
  chan->conn->handshake_state->certs->ed_rsa_crosscert_len =
    rsa_ed_cc_cert_len;
  rsa_ed_cc_cert = NULL;

  int severity;
  /* Note that this warns more loudly about time and validity if we were
   * _trying_ to connect to an authority, not necessarily if we _did_ connect
   * to one. */
  if (started_here &&
      router_digest_is_trusted_dir(TLS_CHAN_TO_BASE(chan)->identity_digest))
    severity = LOG_WARN;
  else
    severity = LOG_PROTOCOL_WARN;

  const ed25519_public_key_t *checked_ed_id = NULL;
  const common_digests_t *checked_rsa_id = NULL;
  or_handshake_certs_check_both(severity,
                                chan->conn->handshake_state->certs,
                                chan->conn->tls,
                                time(NULL),
                                &checked_ed_id,
                                &checked_rsa_id);

  if (!checked_rsa_id)
    ERR("Invalid certificate chain!");

  if (started_here) {
    /* No more information is needed. */

    chan->conn->handshake_state->authenticated = 1;
    chan->conn->handshake_state->authenticated_rsa = 1;
    {
      const common_digests_t *id_digests = checked_rsa_id;
      crypto_pk_t *identity_rcvd;
      if (!id_digests)
        ERR("Couldn't compute digests for key in ID cert");

      identity_rcvd = tor_tls_cert_get_key(id_cert);
      if (!identity_rcvd) {
        ERR("Couldn't get RSA key from ID cert.");
      }
      memcpy(chan->conn->handshake_state->authenticated_rsa_peer_id,
             id_digests->d[DIGEST_SHA1], DIGEST_LEN);
      channel_set_circid_type(TLS_CHAN_TO_BASE(chan), identity_rcvd,
                chan->conn->link_proto < MIN_LINK_PROTO_FOR_WIDE_CIRC_IDS);
      crypto_pk_free(identity_rcvd);
    }

    if (checked_ed_id) {
      chan->conn->handshake_state->authenticated_ed25519 = 1;
      memcpy(&chan->conn->handshake_state->authenticated_ed25519_peer_id,
             checked_ed_id, sizeof(ed25519_public_key_t));
    }

    log_debug(LD_HANDSHAKE, "calling client_learned_peer_id from "
              "process_certs_cell");

    if (connection_or_client_learned_peer_id(chan->conn,
                  chan->conn->handshake_state->authenticated_rsa_peer_id,
                  checked_ed_id) < 0)
      ERR("Problem setting or checking peer id");

    log_info(LD_HANDSHAKE,
             "Got some good certificates on %s: Authenticated it with "
             "RSA%s",
             connection_describe(TO_CONN(chan->conn)),
             checked_ed_id ? " and Ed25519" : "");

    if (!public_server_mode(get_options())) {
      /* If we initiated the connection and we are not a public server, we
       * aren't planning to authenticate at all.  At this point we know who we
       * are talking to, so we can just send a netinfo now. */
      send_netinfo = 1;
    }
  } else {
    /* We can't call it authenticated till we see an AUTHENTICATE cell. */
    log_info(LD_OR,
             "Got some good RSA%s certificates on %s. "
             "Waiting for AUTHENTICATE.",
             checked_ed_id ? " and Ed25519" : "",
             connection_describe(TO_CONN(chan->conn)));
    /* XXXX check more stuff? */
  }

  chan->conn->handshake_state->received_certs_cell = 1;

  if (send_netinfo) {
    if (connection_or_send_netinfo(chan->conn) < 0) {
      log_warn(LD_OR, "Couldn't send netinfo cell");
      connection_or_close_for_error(chan->conn, 0);
      goto err;
    }
  }

 err:
  for (unsigned u = 0; u < ARRAY_LENGTH(x509_certs); ++u) {
    tor_x509_cert_free(x509_certs[u]);
  }
  for (unsigned u = 0; u < ARRAY_LENGTH(ed_certs); ++u) {
    tor_cert_free(ed_certs[u]);
  }
  tor_free(rsa_ed_cc_cert);
  certs_cell_free(cc);
#undef ERR
}

/**
 * Process an AUTH_CHALLENGE cell from a channel_tls_t.
 *
 * This function is called to handle an incoming AUTH_CHALLENGE cell on a
 * channel_tls_t; if we weren't supposed to get one (for example, because we're
 * not the originator of the channel), or it's ill-formed, or we aren't doing
 * a v3 handshake, mark the channel.  If the cell is well-formed but we don't
 * want to authenticate, just drop it.  If the cell is well-formed *and* we
 * want to authenticate, send an AUTHENTICATE cell and then a NETINFO cell.
 */
STATIC void
channel_tls_process_auth_challenge_cell(var_cell_t *cell, channel_tls_t *chan)
{
  int n_types, i, use_type = -1;
  auth_challenge_cell_t *ac = NULL;

  tor_assert(cell);
  tor_assert(chan);
  tor_assert(chan->conn);

#define ERR(s)                                                  \
  do {                                                          \
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,                      \
           "Received a bad AUTH_CHALLENGE cell on %s: %s",      \
           connection_describe(TO_CONN(chan->conn)),            \
           (s));                                                \
    connection_or_close_for_error(chan->conn, 0);               \
    goto done;                                                  \
  } while (0)

  if (chan->conn->base_.state != OR_CONN_STATE_OR_HANDSHAKING_V3)
    ERR("We're not currently doing a v3 handshake");
  if (chan->conn->link_proto < 3)
    ERR("We're not using link protocol >= 3");
  if (!(chan->conn->handshake_state->started_here))
    ERR("We didn't originate this connection");
  if (chan->conn->handshake_state->received_auth_challenge)
    ERR("We already received one");
  if (!(chan->conn->handshake_state->received_certs_cell))
    ERR("We haven't gotten a CERTS cell yet");
  if (cell->circ_id)
    ERR("It had a nonzero circuit ID");

  if (auth_challenge_cell_parse(&ac, cell->payload, cell->payload_len) < 0)
    ERR("It was not well-formed.");

  n_types = ac->n_methods;

  /* Now see if there is an authentication type we can use */
  for (i = 0; i < n_types; ++i) {
    uint16_t authtype = auth_challenge_cell_get_methods(ac, i);
    if (authchallenge_type_is_supported(authtype)) {
      if (use_type == -1 ||
          authchallenge_type_is_better(authtype, use_type)) {
        use_type = authtype;
      }
    }
  }

  chan->conn->handshake_state->received_auth_challenge = 1;

  if (! public_server_mode(get_options())) {
    /* If we're not a public server then we don't want to authenticate on a
       connection we originated, and we already sent a NETINFO cell when we
       got the CERTS cell. We have nothing more to do. */
    goto done;
  }

  if (use_type >= 0) {
    log_info(LD_OR,
             "Got an AUTH_CHALLENGE cell on %s: Sending "
             "authentication type %d",
             connection_describe(TO_CONN(chan->conn)),
             use_type);

    if (connection_or_send_authenticate_cell(chan->conn, use_type) < 0) {
      log_warn(LD_OR,
               "Couldn't send authenticate cell");
      connection_or_close_for_error(chan->conn, 0);
      goto done;
    }
  } else {
    log_info(LD_OR,
             "Got an AUTH_CHALLENGE cell on %s, but we don't "
             "know any of its authentication types. Not authenticating.",
             connection_describe(TO_CONN(chan->conn)));
  }

  if (connection_or_send_netinfo(chan->conn) < 0) {
    log_warn(LD_OR, "Couldn't send netinfo cell");
    connection_or_close_for_error(chan->conn, 0);
    goto done;
  }

 done:
  auth_challenge_cell_free(ac);

#undef ERR
}

/**
 * Process an AUTHENTICATE cell from a channel_tls_t.
 *
 * If it's ill-formed or we weren't supposed to get one or we're not doing a
 * v3 handshake, then mark the connection.  If it does not authenticate the
 * other side of the connection successfully (because it isn't signed right,
 * we didn't get a CERTS cell, etc) mark the connection.  Otherwise, accept
 * the identity of the router on the other side of the connection.
 */
STATIC void
channel_tls_process_authenticate_cell(var_cell_t *cell, channel_tls_t *chan)
{
  var_cell_t *expected_cell = NULL;
  const uint8_t *auth;
  int authlen;
  int authtype;
  int bodylen;

  tor_assert(cell);
  tor_assert(chan);
  tor_assert(chan->conn);

#define ERR(s)                                                  \
  do {                                                          \
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,                      \
           "Received a bad AUTHENTICATE cell on %s: %s",        \
           connection_describe(TO_CONN(chan->conn)),            \
           (s));                                                \
    connection_or_close_for_error(chan->conn, 0);               \
    var_cell_free(expected_cell);                               \
    return;                                                     \
  } while (0)

  if (chan->conn->base_.state != OR_CONN_STATE_OR_HANDSHAKING_V3)
    ERR("We're not doing a v3 handshake");
  if (chan->conn->link_proto < 3)
    ERR("We're not using link protocol >= 3");
  if (chan->conn->handshake_state->started_here)
    ERR("We originated this connection");
  if (chan->conn->handshake_state->received_authenticate)
    ERR("We already got one!");
  if (chan->conn->handshake_state->authenticated) {
    /* Should be impossible given other checks */
    ERR("The peer is already authenticated");
  }
  if (!(chan->conn->handshake_state->received_certs_cell))
    ERR("We never got a certs cell");
  if (chan->conn->handshake_state->certs->id_cert == NULL)
    ERR("We never got an identity certificate");
  if (cell->payload_len < 4)
    ERR("Cell was way too short");

  auth = cell->payload;
  {
    uint16_t type = ntohs(get_uint16(auth));
    uint16_t len = ntohs(get_uint16(auth+2));
    if (4 + len > cell->payload_len)
      ERR("Authenticator was truncated");

    if (! authchallenge_type_is_supported(type))
      ERR("Authenticator type was not recognized");
    authtype = type;

    auth += 4;
    authlen = len;
  }

  if (authlen < V3_AUTH_BODY_LEN + 1)
    ERR("Authenticator was too short");

  expected_cell = connection_or_compute_authenticate_cell_body(
                chan->conn, authtype, NULL, NULL, 1);
  if (! expected_cell)
    ERR("Couldn't compute expected AUTHENTICATE cell body");

  int sig_is_rsa;
  if (authtype == AUTHTYPE_RSA_SHA256_TLSSECRET ||
      authtype == AUTHTYPE_RSA_SHA256_RFC5705) {
    bodylen = V3_AUTH_BODY_LEN;
    sig_is_rsa = 1;
  } else {
    tor_assert(authtype == AUTHTYPE_ED25519_SHA256_RFC5705);
    /* Our earlier check had better have made sure we had room
     * for an ed25519 sig (inadvertently) */
    tor_assert(V3_AUTH_BODY_LEN > ED25519_SIG_LEN);
    bodylen = authlen - ED25519_SIG_LEN;
    sig_is_rsa = 0;
  }
  if (expected_cell->payload_len != bodylen+4) {
    ERR("Expected AUTHENTICATE cell body len not as expected.");
  }

  /* Length of random part. */
  if (BUG(bodylen < 24)) {
    // LCOV_EXCL_START
    ERR("Bodylen is somehow less than 24, which should really be impossible");
    // LCOV_EXCL_STOP
  }

  if (tor_memneq(expected_cell->payload+4, auth, bodylen-24))
    ERR("Some field in the AUTHENTICATE cell body was not as expected");

  if (sig_is_rsa) {
    if (chan->conn->handshake_state->certs->ed_id_sign != NULL)
      ERR("RSA-signed AUTHENTICATE response provided with an ED25519 cert");

    if (chan->conn->handshake_state->certs->auth_cert == NULL)
      ERR("We never got an RSA authentication certificate");

    crypto_pk_t *pk = tor_tls_cert_get_key(
                             chan->conn->handshake_state->certs->auth_cert);
    char d[DIGEST256_LEN];
    char *signed_data;
    size_t keysize;
    int signed_len;

    if (! pk) {
      ERR("Couldn't get RSA key from AUTH cert.");
    }
    crypto_digest256(d, (char*)auth, V3_AUTH_BODY_LEN, DIGEST_SHA256);

    keysize = crypto_pk_keysize(pk);
    signed_data = tor_malloc(keysize);
    signed_len = crypto_pk_public_checksig(pk, signed_data, keysize,
                                           (char*)auth + V3_AUTH_BODY_LEN,
                                           authlen - V3_AUTH_BODY_LEN);
    crypto_pk_free(pk);
    if (signed_len < 0) {
      tor_free(signed_data);
      ERR("RSA signature wasn't valid");
    }
    if (signed_len < DIGEST256_LEN) {
      tor_free(signed_data);
      ERR("Not enough data was signed");
    }
    /* Note that we deliberately allow *more* than DIGEST256_LEN bytes here,
     * in case they're later used to hold a SHA3 digest or something. */
    if (tor_memneq(signed_data, d, DIGEST256_LEN)) {
      tor_free(signed_data);
      ERR("Signature did not match data to be signed.");
    }
    tor_free(signed_data);
  } else {
    if (chan->conn->handshake_state->certs->ed_id_sign == NULL)
      ERR("We never got an Ed25519 identity certificate.");
    if (chan->conn->handshake_state->certs->ed_sign_auth == NULL)
      ERR("We never got an Ed25519 authentication certificate.");

    const ed25519_public_key_t *authkey =
      &chan->conn->handshake_state->certs->ed_sign_auth->signed_key;
    ed25519_signature_t sig;
    tor_assert(authlen > ED25519_SIG_LEN);
    memcpy(&sig.sig, auth + authlen - ED25519_SIG_LEN, ED25519_SIG_LEN);
    if (ed25519_checksig(&sig, auth, authlen - ED25519_SIG_LEN, authkey)<0) {
      ERR("Ed25519 signature wasn't valid.");
    }
  }

  /* Okay, we are authenticated. */
  chan->conn->handshake_state->received_authenticate = 1;
  chan->conn->handshake_state->authenticated = 1;
  chan->conn->handshake_state->authenticated_rsa = 1;
  chan->conn->handshake_state->digest_received_data = 0;
  {
    tor_x509_cert_t *id_cert = chan->conn->handshake_state->certs->id_cert;
    crypto_pk_t *identity_rcvd = tor_tls_cert_get_key(id_cert);
    const common_digests_t *id_digests = tor_x509_cert_get_id_digests(id_cert);
    const ed25519_public_key_t *ed_identity_received = NULL;

    if (! sig_is_rsa) {
      chan->conn->handshake_state->authenticated_ed25519 = 1;
      ed_identity_received =
        &chan->conn->handshake_state->certs->ed_id_sign->signing_key;
      memcpy(&chan->conn->handshake_state->authenticated_ed25519_peer_id,
             ed_identity_received, sizeof(ed25519_public_key_t));
    }

    /* This must exist; we checked key type when reading the cert. */
    tor_assert(id_digests);

    memcpy(chan->conn->handshake_state->authenticated_rsa_peer_id,
           id_digests->d[DIGEST_SHA1], DIGEST_LEN);

    channel_set_circid_type(TLS_CHAN_TO_BASE(chan), identity_rcvd,
               chan->conn->link_proto < MIN_LINK_PROTO_FOR_WIDE_CIRC_IDS);
    crypto_pk_free(identity_rcvd);

    log_debug(LD_HANDSHAKE,
              "Calling connection_or_init_conn_from_address on %s "
              " from %s, with%s ed25519 id.",
              connection_describe(TO_CONN(chan->conn)),
              __func__,
              ed_identity_received ? "" : "out");

    connection_or_init_conn_from_address(chan->conn,
                  &(chan->conn->base_.addr),
                  chan->conn->base_.port,
                  (const char*)(chan->conn->handshake_state->
                    authenticated_rsa_peer_id),
                  ed_identity_received,
                  0);

    log_debug(LD_HANDSHAKE,
             "Got an AUTHENTICATE cell on %s, type %d: Looks good.",
              connection_describe(TO_CONN(chan->conn)),
              authtype);
  }

  var_cell_free(expected_cell);

#undef ERR
}
