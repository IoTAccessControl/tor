/* Copyright (c) 2019 The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitpadding_machines.c
 * \brief Circuit padding state machines
 *
 * Introduce circuit padding machines that will be used by Tor circuits, as
 * specified by proposal 302 "Hiding onion service clients using padding".
 *
 * Right now this file introduces two machines that aim to hide the client-side
 * of onion service circuits against naive classifiers like the ones from the
 * "Circuit Fingerprinting Attacks: Passive Deanonymization of Tor Hidden
 * Services" paper from USENIX. By naive classifiers we mean classifiers that
 * use basic features like "circuit construction circuits" and "incoming and
 * outgoing cell counts" and "duration of activity".
 *
 * In particular, these machines aim to be lightweight and protect against
 * these basic classifiers. They don't aim to protect against more advanced
 * attacks that use deep learning or even correlate various circuit
 * construction events together. Machines that fool such advanced classifiers
 * are also possible, but they can't be so lightweight and might require more
 * WTF-PAD features. So for now we opt for the following two machines:
 *
 * Client-side introduction circuit hiding machine:
 *
 *    This machine hides client-side introduction circuits by making their
 *    circuit construction sequence look like normal general circuits that
 *    download directory information. Furthermore, the circuits are kept open
 *    until all the padding has been sent, since intro circuits are usually
 *    very short lived and this act as a distinguisher. For more info see
 *    circpad_machine_client_hide_intro_circuits() and the sec.
 *
 * Client-side rendezvous circuit hiding machine:
 *
 *    This machine hides client-side rendezvous circuits by making their
 *    circuit construction sequence look like normal general circuits. For more
 *    details see circpad_machine_client_hide_rend_circuits() and the spec.
 *
 * TODO: These are simple machines that carefully manipulate the cells of the
 *   initial circuit setup procedure to make them look like general
 *   circuits. In the future, more states can be baked into their state machine
 *   to do more advanced obfuscation.
 **/

#define CIRCUITPADDING_MACHINES_PRIVATE

#include "core/or/or.h"
#include "feature/nodelist/networkstatus.h"

#include "lib/crypt_ops/crypto_rand.h"

#include "core/or/circuitlist.h"

#include "core/or/circuitpadding_machines.h"
#include "core/or/circuitpadding.h"

/** Create a client-side padding machine that aims to hide IP circuits. In
 *  particular, it keeps intro circuits alive until a bunch of fake traffic has
 *  been pushed through.
 */
void
circpad_machine_client_hide_intro_circuits(smartlist_t *machines_sl)
{
  circpad_machine_spec_t *client_machine
      = tor_malloc_zero(sizeof(circpad_machine_spec_t));

  client_machine->name = "client_ip_circ";

  client_machine->conditions.apply_state_mask = CIRCPAD_CIRC_OPENED;
  client_machine->target_hopnum = 2;

  /* This is a client machine */
  client_machine->is_origin_side = 1;

  /* We only want to pad introduction circuits, and we want to start padding
   * only after the INTRODUCE1 cell has been sent, so set the purposes
   * appropriately.
   *
   * In particular we want introduction circuits to blend as much as possible
   * with general circuits. Most general circuits have the following initial
   * relay cell sequence (outgoing cells marked in [brackets]):
   *
   * [EXTEND2] -> EXTENDED2 -> [EXTEND2] -> EXTENDED2 -> [BEGIN] -> CONNECTED
   *   -> [DATA] -> [DATA] -> DATA -> DATA...(inbound data cells continue)
   *
   * Whereas normal introduction circuits usually look like:
   *
   * [EXTEND2] -> EXTENDED2 -> [EXTEND2] -> EXTENDED2 -> [EXTEND2] -> EXTENDED2
   *   -> [INTRO1] -> INTRODUCE_ACK
   *
   * This means that up to the sixth cell (first line of each sequence above),
   * both general and intro circuits have identical cell sequences. After that
   * we want to mimic the second line sequence of
   *   -> [DATA] -> [DATA] -> DATA -> DATA...(inbound data cells continue)
   *
   * We achieve this by starting padding INTRODUCE1 has been sent. With padding
   * negotiation cells, in the common case of the second line looks like:
   *   -> [INTRO1] -> [PADDING_NEGOTIATE] -> PADDING_NEGOTIATED -> INTRO_ACK
   *
   * Then, the middle node will send between INTRO_MACHINE_MINIMUM_PADDING and
   * INTRO_MACHINE_MAXIMUM_PADDING cells, to match the "...(inbound data cells
   * continue)" portion of the trace (aka the rest of an HTTPS response body).
   */

  /* Start the machine on fresh intro circs. */
  client_machine->conditions.apply_purpose_mask =
    circpad_circ_purpose_to_mask(CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT);

  /* If the client purpose changes back to CIRCUIT_PURPOSE_C_INTRODUCING,
   * or transitions to CIRCUIT_PURPOSE_C_INTRODUCE_ACKED, keep the machine
   * alive, but do not launch new machines for these purposes. Also
   * keep the machine around if it is in the CIRCUIT_PADDING purpose
   * (but do not try to take over other machines in that purpose). */
  client_machine->conditions.keep_purpose_mask =
    circpad_circ_purpose_to_mask(CIRCUIT_PURPOSE_C_INTRODUCE_ACKED) |
    circpad_circ_purpose_to_mask(CIRCUIT_PURPOSE_C_CIRCUIT_PADDING);

  /* Keep the circuit alive even after the introduction has been finished,
   * otherwise the short-term lifetime of the circuit will blow our cover */
  client_machine->manage_circ_lifetime = 1;

  /* Set padding machine limits to help guard against excessive padding */
  client_machine->allowed_padding_count = INTRO_MACHINE_MAXIMUM_PADDING;
  client_machine->max_padding_percent = 1;

  /* Two states: START, OBFUSCATE_CIRC_SETUP (and END) */
  circpad_machine_states_init(client_machine, 2);

  /* For the origin-side machine, we transition to OBFUSCATE_CIRC_SETUP after
   * sending PADDING_NEGOTIATE, and we stay there (without sending any padding)
   * until we receive a STOP from the other side. */
  client_machine->states[CIRCPAD_STATE_START].
    next_state[CIRCPAD_EVENT_NONPADDING_SENT] =
    CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP;

  /* origin-side machine has no event reactions while in
   * CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP, so no more state transitions here. */

  /* The client side should never send padding, so it does not need
   * to specify token removal, or a histogram definition or state lengths.
   * That is all controlled by the middle node. */

  /* Register the machine */
  client_machine->machine_num = smartlist_len(machines_sl);
  circpad_register_padding_machine(client_machine, machines_sl);

  log_info(LD_CIRC,
           "Registered client intro point hiding padding machine (%u)",
           client_machine->machine_num);
}

/** Create a relay-side padding machine that aims to hide IP circuits. See
 *  comments on the function above for more details on the workings of the
 *  machine. */
void
circpad_machine_relay_hide_intro_circuits(smartlist_t *machines_sl)
{
  circpad_machine_spec_t *relay_machine
      = tor_malloc_zero(sizeof(circpad_machine_spec_t));

  relay_machine->name = "relay_ip_circ";

  relay_machine->conditions.apply_state_mask = CIRCPAD_CIRC_OPENED;

  /* This is a relay-side machine */
  relay_machine->is_origin_side = 0;

  /* We want to negotiate END from this side after all our padding is done, so
   * that the origin-side machine goes into END state, and eventually closes
   * the circuit. */
  relay_machine->should_negotiate_end = 1;

  /* Set padding machine limits to help guard against excessive padding */
  relay_machine->allowed_padding_count = INTRO_MACHINE_MAXIMUM_PADDING;
  relay_machine->max_padding_percent = 1;

  /* Two states: START, OBFUSCATE_CIRC_SETUP (and END) */
  circpad_machine_states_init(relay_machine, 2);

  /* For the relay-side machine, we want to transition
   * START -> OBFUSCATE_CIRC_SETUP upon first non-padding
   * cell sent (PADDING_NEGOTIATED in this case).  */
  relay_machine->states[CIRCPAD_STATE_START].
    next_state[CIRCPAD_EVENT_NONPADDING_SENT] =
    CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP;

  /* For the relay-side, we want to transition from OBFUSCATE_CIRC_SETUP to END
   * state when the length finishes. */
  relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
      next_state[CIRCPAD_EVENT_LENGTH_COUNT] = CIRCPAD_STATE_END;

  /* Now let's define the OBF -> OBF transitions that maintain our padding
   * flow:
   *
   * For the relay-side machine, we want to keep on sending padding bytes even
   * when nothing else happens on this circuit. */
  relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    next_state[CIRCPAD_EVENT_PADDING_SENT] =
    CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP;
  /* For the relay-side machine, we need this transition so that we re-enter
     the state, after PADDING_NEGOTIATED is sent. Otherwise, the remove token
     function will disable the timer, and nothing will restart it since there
     is no other motion on an intro circuit. */
  relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    next_state[CIRCPAD_EVENT_NONPADDING_SENT] =
    CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP;

  /* Token removal strategy for OBFUSCATE_CIRC_SETUP state: Don't
   * remove any tokens.
   *
   * We rely on the state length sampling and not token removal, to avoid
   * the mallocs required to copy the histograms for token removal,
   * and to avoid monotime calls needed to determine histogram
   * bins for token removal. */
  relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    token_removal = CIRCPAD_TOKEN_REMOVAL_NONE;

  /* Figure out the length of the OBFUSCATE_CIRC_SETUP state so that it's
   * randomized. The relay side will send between INTRO_MACHINE_MINIMUM_PADDING
   * and INTRO_MACHINE_MAXIMUM_PADDING padding cells towards the client. */
  relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    length_dist.type = CIRCPAD_DIST_UNIFORM;
  relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    length_dist.param1 = INTRO_MACHINE_MINIMUM_PADDING;
  relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    length_dist.param2 = INTRO_MACHINE_MAXIMUM_PADDING;

  /* Configure histogram */
  relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
     histogram_len = 2;

  /* For the relay-side machine we want to batch padding instantly to pretend
   * its an incoming directory download. So set the histogram edges tight:
   * (1, 10ms, infinity). */
  relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    histogram_edges[0] = 1000;
  relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    histogram_edges[1] = 10000;

  /* We put all our tokens in bin 0, which means we want 100% probability
   * for choosing a inter-packet delay of between 1000 and 10000 microseconds
   * (1 to 10ms). Since we only have 1 bin, it doesn't matter how many tokens
   * there are, 1000 out of 1000 is 100% */
  relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    histogram[0] = 1000;

  /* just one bin, so setup the total tokens */
  relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    histogram_total_tokens =
      relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].histogram[0];

  /* Register the machine */
  relay_machine->machine_num = smartlist_len(machines_sl);
  circpad_register_padding_machine(relay_machine, machines_sl);

  log_info(LD_CIRC,
           "Registered relay intro circuit hiding padding machine (%u)",
           relay_machine->machine_num);
}

/************************** Rendezvous-circuit machine ***********************/

/** Create a client-side padding machine that aims to hide rendezvous
 *  circuits.*/
void
circpad_machine_client_hide_rend_circuits(smartlist_t *machines_sl)
{
  circpad_machine_spec_t *client_machine
      = tor_malloc_zero(sizeof(circpad_machine_spec_t));

  client_machine->name = "client_rp_circ";

  /* Only pad after the circuit has been built and pad to the middle */
  client_machine->conditions.apply_state_mask = CIRCPAD_CIRC_OPENED;
  client_machine->target_hopnum = 2;

  /* This is a client machine */
  client_machine->is_origin_side = 1;

  /* We only want to pad rendezvous circuits, and we want to start padding only
   * after the rendezvous circuit has been established.
   *
   * Following a similar argument as for intro circuits, we are aiming for
   * padded rendezvous circuits to blend in with the initial cell sequence of
   * general circuits which usually look like this:
   *
   * [EXTEND2] -> EXTENDED2 -> [EXTEND2] -> EXTENDED2 -> [BEGIN] -> CONNECTED
   *    -> [DATA] -> [DATA] -> DATA -> DATA...(incoming cells continue)
   *
   * Whereas normal rendezvous circuits usually look like:
   *
   * [EXTEND2] -> EXTENDED2 -> [EXTEND2] -> EXTENDED2 -> [EST_REND] -> REND_EST
   *    -> REND2 -> [BEGIN]
   *
   * This means that up to the sixth cell (in the first line), both general and
   * rend circuits have identical cell sequences.
   *
   * After that we want to mimic a [DATA] -> [DATA] -> DATA -> DATA sequence.
   *
   * With padding negotiation right after the REND_ESTABLISHED, the sequence
   * becomes:
   *
   * [EXTEND2] -> EXTENDED2 -> [EXTEND2] -> EXTENDED2 -> [EST_REND] -> REND_EST
   *    -> [PADDING_NEGOTIATE] -> [DROP] -> PADDING_NEGOTIATED -> DROP...
   *
   * After which normal application DATA cells continue on the circuit.
   *
   * Hence this way we make rendezvous circuits look like general circuits up
   * till the end of the circuit setup. */
  client_machine->conditions.apply_purpose_mask =
    circpad_circ_purpose_to_mask(CIRCUIT_PURPOSE_C_REND_JOINED)|
    circpad_circ_purpose_to_mask(CIRCUIT_PURPOSE_C_REND_READY)|
    circpad_circ_purpose_to_mask(CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED);

  /* Set padding machine limits to help guard against excessive padding */
  client_machine->allowed_padding_count = 1;
  client_machine->max_padding_percent = 1;

  /* Two states: START, OBFUSCATE_CIRC_SETUP (and END) */
  circpad_machine_states_init(client_machine, 2);

  /* START -> OBFUSCATE_CIRC_SETUP transition upon sending the first
   * non-padding cell (which is PADDING_NEGOTIATE) */
  client_machine->states[CIRCPAD_STATE_START].
    next_state[CIRCPAD_EVENT_NONPADDING_SENT] =
    CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP;

  /* OBFUSCATE_CIRC_SETUP -> END transition when we send our first
   * padding packet and/or hit the state length (the state length is 1). */
  client_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
      next_state[CIRCPAD_EVENT_PADDING_RECV] = CIRCPAD_STATE_END;
  client_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
      next_state[CIRCPAD_EVENT_LENGTH_COUNT] = CIRCPAD_STATE_END;

  /* Don't use a token removal strategy since we don't want to use monotime
   * functions and we want to avoid mallocing histogram copies. We want
   * this machine to be light. */
  client_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    token_removal = CIRCPAD_TOKEN_REMOVAL_NONE;

  /* Instead, to control the volume of padding (we just want to send a single
   * padding cell) we will use a static state length. We just want one token,
   * since we want to make the following pattern:
   * [PADDING_NEGOTIATE] -> [DROP] -> PADDING_NEGOTIATED -> DROP */
  client_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    length_dist.type = CIRCPAD_DIST_UNIFORM;
  client_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    length_dist.param1 = 1;
  client_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    length_dist.param2 = 2; // rand(1,2) is always 1

  /* Histogram is: (0 msecs, 1 msec, infinity). We want this to be fast so
   * that we send our outgoing [DROP] before the PADDING_NEGOTIATED comes
   * back from the relay side. */
  client_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    histogram_len = 2;
  client_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    histogram_edges[0] = 0;
  client_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    histogram_edges[1] = 1000;

  /* We want a 100% probability of choosing an inter-packet delay of
   * between 0 and 1ms. Since we don't use token removal,
   * the number of tokens does not matter. (And also, state_length
   * governs how many packets we send). */
  client_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    histogram[0] = 1;
  client_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    histogram_total_tokens = 1;

  /* Register the machine */
  client_machine->machine_num = smartlist_len(machines_sl);
  circpad_register_padding_machine(client_machine, machines_sl);

  log_info(LD_CIRC,
           "Registered client rendezvous circuit hiding padding machine (%u)",
           client_machine->machine_num);
}

/** Create a relay-side padding machine that aims to hide IP circuits.
 *
 *  This is meant to follow the client-side machine.
 */
void
circpad_machine_relay_hide_rend_circuits(smartlist_t *machines_sl)
{
  circpad_machine_spec_t *relay_machine
    = tor_malloc_zero(sizeof(circpad_machine_spec_t));

  relay_machine->name = "relay_rp_circ";

  /* Only pad after the circuit has been built and pad to the middle */
  relay_machine->conditions.min_hops = 2;
  relay_machine->conditions.apply_state_mask = CIRCPAD_CIRC_OPENED;

  /* This is a relay-side machine */
  relay_machine->is_origin_side = 0;

  /* Set padding machine limits to help guard against excessive padding */
  relay_machine->allowed_padding_count = 1;
  relay_machine->max_padding_percent = 1;

  /* Two states: START, OBFUSCATE_CIRC_SETUP (and END) */
  circpad_machine_states_init(relay_machine, 2);

  /* START -> OBFUSCATE_CIRC_SETUP transition upon sending the first
   * non-padding cell (which is PADDING_NEGOTIATED) */
  relay_machine->states[CIRCPAD_STATE_START].
    next_state[CIRCPAD_EVENT_NONPADDING_SENT] =
    CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP;

  /* OBFUSCATE_CIRC_SETUP -> END transition when we send our first
   * padding packet and/or hit the state length (the state length is 1). */
  relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
      next_state[CIRCPAD_EVENT_PADDING_SENT] = CIRCPAD_STATE_END;
  relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
      next_state[CIRCPAD_EVENT_LENGTH_COUNT] = CIRCPAD_STATE_END;

  /* Don't use a token removal strategy since we don't want to use monotime
   * functions and we want to avoid mallocing histogram copies. We want
   * this machine to be light. */
  relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    token_removal = CIRCPAD_TOKEN_REMOVAL_NONE;

  /* Instead, to control the volume of padding (we just want to send a single
   * padding cell) we will use a static state length. We just want one token,
   * since we want to make the following pattern:
   * [PADDING_NEGOTIATE] -> [DROP] -> PADDING_NEGOTIATED -> DROP */
  relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    length_dist.type = CIRCPAD_DIST_UNIFORM;
  relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    length_dist.param1 = 1;
  relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    length_dist.param2 = 2; // rand(1,2) is always 1

  /* Histogram is: (0 msecs, 1 msec, infinity). We want this to be fast so
   * that the outgoing DROP cell is sent immediately after the
   * PADDING_NEGOTIATED. */
  relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    histogram_len = 2;
  relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    histogram_edges[0] = 0;
  relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    histogram_edges[1] = 1000;

  /* We want a 100% probability of choosing an inter-packet delay of
   * between 0 and 1ms. Since we don't use token removal,
   * the number of tokens does not matter. (And also, state_length
   * governs how many packets we send). */
  relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    histogram[0] = 1;
  relay_machine->states[CIRCPAD_STATE_OBFUSCATE_CIRC_SETUP].
    histogram_total_tokens = 1;

  /* Register the machine */
  relay_machine->machine_num = smartlist_len(machines_sl);
  circpad_register_padding_machine(relay_machine, machines_sl);

  log_info(LD_CIRC,
           "Registered relay rendezvous circuit hiding padding machine (%u)",
           relay_machine->machine_num);
}

// https://github.com/pylls/tor/compare/439ca48...34fcc03
// https://github.com/pylls/tor/blob/circuit-padding-ape-machine/src/core/or/circuitpadding_machines.c#L460
/**************** Adaptive Padding Early (APE) machines ****************
*
* Setting: client <---> relay <---> destination
*
* APE (and WTF-PAD) consists of four machines, two running at the client and two
* at the middle relay, acting on the same circuit:
*
* - at the client, circpad_machine_client_wf_ape_send() acts on the client
*   sending non-padding cells to the destination, and
*   circpad_machine_client_wf_ape_recv() acts on the client receiving
*   non-padding cells from the destination.
*
* - at the relay, circpad_machine_relay_wf_ape_send() acts on the destination
*   sending non-padding cells to the client, and
*   circpad_machine_relay_wf_ape_recv() acts on the destination receiving
*   non-padding cells to the client. 
*
* Note that APE, like WTF-PAD, is highly likely to be _ineffective_ against WF
* attacks based on deep learning. This implementation is just as a demonstrator
* of the circuit padding framework. No effort has been spent on optimizing
* distributions. 
*/
void circpad_machine_relay_wf_ape_send(smartlist_t *machines_sl) 
{
  circpad_machine_spec_t *relay_machine = circpad_machine_common_wf_ape_make();
  circpad_machine_common_adaptive_padding_machine(CIRCPAD_EVENT_NONPADDING_SENT,                                                relay_machine);
  relay_machine->name = "relay_wf_ape_send";
  relay_machine->is_origin_side = 0; // relay-side

  // a small budget, don't think extending bursts are all that useful
  relay_machine->allowed_padding_count = 200; 


  // prevent the machine from sending a padding cell too early (FIXME: bug?)
  relay_machine->states[CIRCPAD_STATE_START].
      next_state[CIRCPAD_EVENT_NONPADDING_SENT] = CIRCPAD_STATE_IGNORE;
  relay_machine->states[CIRCPAD_STATE_START].
      next_state[CIRCPAD_EVENT_NONPADDING_RECV] = CIRCPAD_STATE_BURST;

  /* ===== BURST ===== */

  /* This is the sampled time before transitioning to the gap state (we
  * transition on timeout due to sending a padding cell). Should be short, order
  * a few ms. Uses a random uniform dist with a max at most 10 ms. */
  relay_machine->states[CIRCPAD_STATE_BURST].
  iat_dist.type = CIRCPAD_DIST_UNIFORM;
  relay_machine->states[CIRCPAD_STATE_BURST].
  iat_dist.param1 = 0;
  relay_machine->states[CIRCPAD_STATE_BURST].
  iat_dist.param2 = 10000 * crypto_fast_rng_get_double(get_thread_fast_rng());
  relay_machine->states[CIRCPAD_STATE_BURST].
  dist_max_sample_usec = relay_machine->states[CIRCPAD_STATE_BURST].iat_dist.param2;

  // results in 50% chance of transitioning back to start from burst
  circpad_machine_common_wf_ape_prob_back(relay_machine, 1);

  /* ===== GAP ===== */

  /* The IAT between the cells that make up our fake (extended) HTTP response.
  * This should be small, it's basically variance between middle and
  * destination. Assuming a full typical MTU, several cells of data (typically
  * ~3) should have zero delay.
  *
  * Using a uniform dist with a max at most 2 ms. */
  relay_machine->states[CIRCPAD_STATE_GAP].
  iat_dist.type = CIRCPAD_DIST_UNIFORM;
  relay_machine->states[CIRCPAD_STATE_GAP].
  iat_dist.param1 = 0;
  relay_machine->states[CIRCPAD_STATE_GAP].
  iat_dist.param2 = 2000 * crypto_fast_rng_get_double(get_thread_fast_rng());
  relay_machine->states[CIRCPAD_STATE_GAP].
  dist_max_sample_usec = relay_machine->states[CIRCPAD_STATE_GAP].iat_dist.param2;

  /* The length of the GAP state is more tricky: it's represents downloads of
  * everything from small JS/CSS files, API responses in RESTful protocols, to
  * larger common assets like images. 
  *
  * According to https://httparchive.org/reports/page-weight, in August 2019,
  * the median desktop website was 1936.7 KB and transferred over 74 requests.
  * This gives us around 20-30 KB per resource, so around 40-60 cells very
  * roughly. We only want to do small extensions here. */
  relay_machine->states[CIRCPAD_STATE_GAP].
  length_dist.type = CIRCPAD_DIST_UNIFORM;
  relay_machine->states[CIRCPAD_STATE_GAP].
  length_dist.param1 = 0; // recall, the transition already sent a cell
  relay_machine->states[CIRCPAD_STATE_GAP].
  length_dist.param2 = 20 * crypto_fast_rng_get_double(get_thread_fast_rng());
  relay_machine->states[CIRCPAD_STATE_BURST].length_includes_nonpadding = 0;

  // register the machine
  relay_machine->machine_num = smartlist_len(machines_sl);
  circpad_register_padding_machine(relay_machine, machines_sl);
  log_info(LD_CIRC,
           "Registered relay WF APE padding machine send events (%u)",
           relay_machine->machine_num);
}

/** dest -> [relay] -> |add paddings| -> client
 * Create an APE relay-side padding machine, receive event (client->dest). The
 * goal of this machine is to create completely fake responses of padding cells
 * from the destination to the client.
 */
void
circpad_machine_relay_wf_ape_recv(smartlist_t *machines_sl)
{
  circpad_machine_spec_t *relay_machine = circpad_machine_common_wf_ape_make();
  circpad_machine_common_adaptive_padding_machine(CIRCPAD_EVENT_NONPADDING_RECV,                                                relay_machine);
  relay_machine->name = "relay_wf_ape_recv";
  relay_machine->is_origin_side = 0; // relay-side
  relay_machine->machine_index = 1; // index 0 for send, 1 for recv

  /* According to https://httparchive.org/reports/page-weight, in August 2019,
  * the median desktop website was 1936.7 KB. Allowing 1000 padding cells should
  * be about 25%, which is exceptionally good for a WF defense as-is. */
  relay_machine->allowed_padding_count = 1000; 

  /* ===== BURST ===== */

  /* This is the sampled time before transitioning to the gap state (we
  * transition on timeout due to sending a padding cell). The goal here is to
  * inject a fake burst as a response to a cell sent from the client. First, we
  * use the RTT-estimate here as a lower bound since it estimates the RTT
  * between relay and destination. What our distribution has to capture is
  * variance.
  *
  * Assume it's reasonable to wait in the order of a few ms (beyond RRT). Uses a
  * random uniform dist with a max at most 10 ms. */
  relay_machine->states[CIRCPAD_STATE_BURST].
  iat_dist.type = CIRCPAD_DIST_UNIFORM;
  relay_machine->states[CIRCPAD_STATE_BURST].
  iat_dist.param1 = 0;
  relay_machine->states[CIRCPAD_STATE_BURST].
  iat_dist.param2 = 10000 * crypto_fast_rng_get_double(get_thread_fast_rng());
  relay_machine->states[CIRCPAD_STATE_BURST].use_rtt_estimate = 1;
  relay_machine->states[CIRCPAD_STATE_BURST].
  dist_max_sample_usec = relay_machine->states[CIRCPAD_STATE_BURST].iat_dist.param2;

  // results in 25% chance of transitioning back to start from burst
  circpad_machine_common_wf_ape_prob_back(relay_machine, 3);

  /* ===== GAP ===== */

  /* The IAT between the cells that make up our fake HTTP response. This should
  * be small, it's basically variance between middle and destination. Assuming a
  * full typical MTU, several cells of data (typically ~3) should have zero
  * delay.
  *
  * Using a uniform dist with a max at most 2 ms. */
  relay_machine->states[CIRCPAD_STATE_GAP].
  iat_dist.type = CIRCPAD_DIST_UNIFORM;
  relay_machine->states[CIRCPAD_STATE_GAP].
  iat_dist.param1 = 0;
  relay_machine->states[CIRCPAD_STATE_GAP].
  iat_dist.param2 = 2000 * crypto_fast_rng_get_double(get_thread_fast_rng());
  relay_machine->states[CIRCPAD_STATE_GAP].dist_max_sample_usec = 
      relay_machine->states[CIRCPAD_STATE_GAP].iat_dist.param2;

  /* The length of the GAP state is more tricky: it's represents downloads of
  * everything from small JS/CSS files, API responses in RESTful protocols, to
  * larger common assets like images. 
  *
  * According to https://httparchive.org/reports/page-weight, in August 2019,
  * the median desktop website was 1936.7 KB and transferred over 74 requests.
  * This gives us around 20-30 KB per resource, so around 40-60 cells very
  * roughly. We use this as an upper bound for a random uniform dist. */
  relay_machine->states[CIRCPAD_STATE_GAP].
  length_dist.type = CIRCPAD_DIST_UNIFORM;
  relay_machine->states[CIRCPAD_STATE_GAP].
  length_dist.param1 = 0; // recall, the transition already sent a cell
  relay_machine->states[CIRCPAD_STATE_GAP].
  length_dist.param2 = 60 * crypto_fast_rng_get_double(get_thread_fast_rng());
  relay_machine->states[CIRCPAD_STATE_BURST].length_includes_nonpadding = 0;

  // register the machine
  relay_machine->machine_num = smartlist_len(machines_sl);
  circpad_register_padding_machine(relay_machine, machines_sl);
  log_info(LD_CIRC,
           "Registered relay WF APE padding machine receive events (%u)",
           relay_machine->machine_num);
}

/**
 * Create an APE client-side padding machine, send event (client->dest). The
 * goal of this machine is to make it appear like the client is sending more (or
 * larger) HTTP requests to the destination.
 */
void
circpad_machine_client_wf_ape_send(smartlist_t *machines_sl)
{
  circpad_machine_spec_t *client_machine = circpad_machine_common_wf_ape_make();
  circpad_machine_common_adaptive_padding_machine(CIRCPAD_EVENT_NONPADDING_SENT,                                                client_machine);
  client_machine->name = "client_wf_ape_send";
  client_machine->is_origin_side = 1; // client-side

  /* about 0.25 MiB, a lot for what should be mostly HTTP requests, but not much
  * in terms of real bandwidth with mostly symmetric connections abound */
  client_machine->allowed_padding_count = 500; 

  // only for general purpose circuits
  client_machine->conditions.apply_purpose_mask =
    circpad_circ_purpose_to_mask(CIRCUIT_PURPOSE_C_GENERAL)|
    circpad_circ_purpose_to_mask(CIRCUIT_PURPOSE_C_CIRCUIT_PADDING);

  /* ===== BURST ===== */

  /* This is the sampled time we wait before transitioning to the gap state. The
  * time should be really small on the client, it's basically the time between
  * TB giving us another cells worth of data to send or not. If we wait too long
  * it looks unrealistic. Note that we enter burst mode from the
  * CIRCPAD_EVENT_NONPADDING_SENT event, which means that tor has done a lot of
  * processing of the data already. For details:
  * https://trac.torproject.org/projects/tor/ticket/29494
  *
  * Ultimately, What we aim to encode in the client is more (or larger) HTTP GET
  * requests from the client to the destination website.
  *
  * Order should be below 1 ms, so we wait at least 100 us (to give tor a chance
  * to queue application data), but then have a random distribution between
  * [0,1] ms. */
  client_machine->states[CIRCPAD_STATE_BURST].
  iat_dist.type = CIRCPAD_DIST_UNIFORM;
  client_machine->states[CIRCPAD_STATE_BURST].
  iat_dist.param1 = 0;
  client_machine->states[CIRCPAD_STATE_BURST].
  iat_dist.param2 = 1000 * crypto_fast_rng_get_double(get_thread_fast_rng());
  client_machine->states[CIRCPAD_STATE_BURST].
  dist_added_shift_usec = 100;
  client_machine->states[CIRCPAD_STATE_BURST].
  dist_max_sample_usec = client_machine->states[CIRCPAD_STATE_BURST].iat_dist.param2 + 
  client_machine->states[CIRCPAD_STATE_BURST].dist_added_shift_usec;

  // results in 25% chance of transitioning back to start from burst
  circpad_machine_common_wf_ape_prob_back(client_machine, 3);

  /* ===== GAP ===== */

  /* The IAT between the cells that make up additional (or larger) HTTP GET
  * requests from the client. This time should be negligible. We let tor's
  * internal plumbing cause realistic delays between the cells as they are sent
  * out on the wire. No point in randomizing distribution to sample from. 
  *
  * Set to [10,50] us. */
  client_machine->states[CIRCPAD_STATE_GAP].
  iat_dist.type = CIRCPAD_DIST_UNIFORM;
  client_machine->states[CIRCPAD_STATE_GAP].
  iat_dist.param1 = 0;
  client_machine->states[CIRCPAD_STATE_GAP].
  iat_dist.param2 = 40;
  client_machine->states[CIRCPAD_STATE_GAP].
  dist_added_shift_usec = 10;
  client_machine->states[CIRCPAD_STATE_GAP].
  dist_max_sample_usec = client_machine->states[CIRCPAD_STATE_GAP].iat_dist.param2 + 
  client_machine->states[CIRCPAD_STATE_GAP].dist_added_shift_usec;

  /* Here we sample the number of cells that make up our additional (or larger)
  * HTTP requests.
  *
  * http://dev.chromium.org/spdy/spdy-whitepaper states that "Request headers
  * today vary in size from ~200 bytes to over 2KB", and that "typical header
  * sizes of 700-800 bytes is common". This is about 1½-4 cells, and we already
  * sent one cell (as part of the transition). Also, we want to potentially
  * encode more than one request.
  *
  * A geometric dist with p = 0.3 gives mean 3.33 and variance 7.78. We
  * uniformly randomize p around [0.2,0.4]. We put an upper bound of 40 cells to
  * prevent excessive padding, don't want to burn all our budget here. */
  client_machine->states[CIRCPAD_STATE_GAP].
  length_dist.type = CIRCPAD_DIST_GEOMETRIC;
  client_machine->states[CIRCPAD_STATE_GAP].
  length_dist.param1 = MAX(0.2, MIN(0.4, 
                           crypto_fast_rng_get_double(get_thread_fast_rng())));
  client_machine->states[CIRCPAD_STATE_GAP].max_length = 40;
  client_machine->states[CIRCPAD_STATE_GAP].length_includes_nonpadding = 0;

  // register the machine
  client_machine->machine_num = smartlist_len(machines_sl);
  circpad_register_padding_machine(client_machine, machines_sl);
  log_info(LD_CIRC,
           "Registered client WF APE padding machine send events (%u)",
           client_machine->machine_num);
}

/**
 * Create an APE client-side padding machine, receive event (dest->client). The
 * goal of this machine is to inject fake HTTP requests from the client.
 */
void
circpad_machine_client_wf_ape_recv(smartlist_t *machines_sl)
{
  circpad_machine_spec_t *client_machine = circpad_machine_common_wf_ape_make();
  circpad_machine_common_adaptive_padding_machine(CIRCPAD_EVENT_NONPADDING_RECV, client_machine);
  client_machine->name = "client_wf_ape_recv";
  client_machine->is_origin_side = 1; // client-side
  client_machine->machine_index = 1; // index 0 for send, 1 for recv

  /* about 0.25 MiB, a lot for what should be mostly HTTP requests, but not much
  * in terms of real bandwidth with mostly symmetric connections abound */
  client_machine->allowed_padding_count = 500; 

  // only for general purpose circuits
  client_machine->conditions.apply_purpose_mask =
    circpad_circ_purpose_to_mask(CIRCUIT_PURPOSE_C_GENERAL)|
    circpad_circ_purpose_to_mask(CIRCUIT_PURPOSE_C_CIRCUIT_PADDING);

  /* ===== BURST ===== */

  /* The time for client to send to TB, process, and send a cell back. Giving at
  *least 200 us to process, beyond that a random dist between [0,1] ms. */
  client_machine->states[CIRCPAD_STATE_BURST].
  iat_dist.type = CIRCPAD_DIST_UNIFORM;
  client_machine->states[CIRCPAD_STATE_BURST].
  iat_dist.param1 = 0;
  client_machine->states[CIRCPAD_STATE_BURST].
  iat_dist.param2 = 1000 * crypto_fast_rng_get_double(get_thread_fast_rng());
  client_machine->states[CIRCPAD_STATE_BURST].
  dist_added_shift_usec = 200;
  client_machine->states[CIRCPAD_STATE_BURST].
  dist_max_sample_usec = client_machine->states[CIRCPAD_STATE_BURST].iat_dist.param2 + 
  client_machine->states[CIRCPAD_STATE_BURST].dist_added_shift_usec;

  // results in 25% chance of transitioning back to start from burst
  circpad_machine_common_wf_ape_prob_back(client_machine, 3);

  /* ===== GAP ===== */

  // identical to circpad_machine_client_wf_ape_send()
  client_machine->states[CIRCPAD_STATE_GAP].
  iat_dist.type = CIRCPAD_DIST_UNIFORM;
  client_machine->states[CIRCPAD_STATE_GAP].
  iat_dist.param1 = 0;
  client_machine->states[CIRCPAD_STATE_GAP].
  iat_dist.param2 = 40;
  client_machine->states[CIRCPAD_STATE_GAP].
  dist_added_shift_usec = 10;
  client_machine->states[CIRCPAD_STATE_GAP].
  dist_max_sample_usec = client_machine->states[CIRCPAD_STATE_GAP].iat_dist.param2 + 
  client_machine->states[CIRCPAD_STATE_GAP].dist_added_shift_usec;
  
  client_machine->states[CIRCPAD_STATE_GAP].
  length_dist.type = CIRCPAD_DIST_GEOMETRIC;
  client_machine->states[CIRCPAD_STATE_GAP].
  length_dist.param1 = MAX(0.2, MIN(0.4, 
                           crypto_fast_rng_get_double(get_thread_fast_rng())));
  client_machine->states[CIRCPAD_STATE_GAP].max_length = 40;
  client_machine->states[CIRCPAD_STATE_GAP].length_includes_nonpadding = 0;

  // register the machine
  client_machine->machine_num = smartlist_len(machines_sl);
  circpad_register_padding_machine(client_machine, machines_sl);
  log_info(LD_CIRC,
           "Registered client WF APE padding machine recieve events (%u)",
           client_machine->machine_num);
}

/**
 * Create an APE padding machine with the common parts for both clients and
 * relays, regardless if for of send or receive events.
 */
circpad_machine_spec_t *
circpad_machine_common_wf_ape_make(void)
{
  circpad_machine_spec_t *m
  = tor_malloc_zero(sizeof(circpad_machine_spec_t));

  // pad to/from the middle relay when the circuit is open and has streams
  m->target_hopnum = 2;
  m->conditions.min_hops = 2;
  m->conditions.apply_state_mask = CIRCPAD_CIRC_STREAMS;

  // this is about 50% overhead, 1/3 padding, 2/3 non-padding
  m->max_padding_percent = 33;

  /* explicit default to index 0, set to 1 on _recv machines: this is needed for
   * the circuit framework to run both padding machines on the same circuit */
  m->machine_index = 0;

  return m;
  }

/**
   In burst state, use the length count to make the transition back to the start
   state probabilistic. This is used in place of the infinity bin in a
   histogram, as in WTF-PAD. 
   Results in 1/(l+1) probability of transitioning to the start state.
 */
void
circpad_machine_common_wf_ape_prob_back(circpad_machine_spec_t *m, double l)
{
  m->states[CIRCPAD_STATE_BURST].
  length_dist.type = CIRCPAD_DIST_UNIFORM;
  m->states[CIRCPAD_STATE_BURST].
  length_dist.param1 = 0;
  m->states[CIRCPAD_STATE_BURST].
  length_dist.param2 = l; 
  m->states[CIRCPAD_STATE_BURST].length_includes_nonpadding = 0;
}

/**
 * Set the states of a machine to that of the Adaptive Padding machine as shown
 * in Figure 2, https://arxiv.org/pdf/1512.00524.pdf, "Toward an Efficient
 * Website Fingerprinting Defense" by Juarez et al.
 *
 * Histograms and/or distributions are not set for any of the states.
 * Transitions occur on either sampled infinity or used up length count, to
 * support both WTF-PAD and APE-like designs.
 *
 * The event argument specifies the primary event on when to transition from
 * start->burst, burst->burst, and gap->burst. 
 *
 * In Figure 2, "psh" refers to when "a message pushed from the application (Tor
 * Browser) to the PT client.", which in our case means that:
 * - for the client, cell from TB towards relay
 * - for the relay, cell from destination towards client
 *
 * The corresponding event in the framework is CIRCPAD_EVENT_NONPADDING_SENT.
 *
 * For the additional receive state machines, use CIRCPAD_EVENT_NONPADDING_RECV.
 */
void
circpad_machine_common_adaptive_padding_machine(circpad_event_t event,
                                                circpad_machine_spec_t *m)
{
  // we have three states: start, burst, and gap
  circpad_machine_states_init(m, 3);

  // main event to always transition to burst-state on
  m->states[CIRCPAD_STATE_START].
      next_state[event] = CIRCPAD_STATE_BURST;
  m->states[CIRCPAD_STATE_BURST].
      next_state[event] = CIRCPAD_STATE_BURST;
  m->states[CIRCPAD_STATE_GAP].
      next_state[event] = CIRCPAD_STATE_BURST;

  // transition from burst to gap state on sending padding (timeout)
  m->states[CIRCPAD_STATE_BURST].
      next_state[CIRCPAD_EVENT_PADDING_SENT] = CIRCPAD_STATE_GAP;

  /* Transition "backwards" in the machine on:
   * - sampled infinity (mainly histogram), or
   * - used up length count (useful for distributions) */
  m->states[CIRCPAD_STATE_GAP].
      next_state[CIRCPAD_EVENT_INFINITY] = CIRCPAD_STATE_BURST;
  m->states[CIRCPAD_STATE_BURST].
      next_state[CIRCPAD_EVENT_INFINITY] = CIRCPAD_STATE_START;
  m->states[CIRCPAD_STATE_GAP].
      next_state[CIRCPAD_EVENT_LENGTH_COUNT] = CIRCPAD_STATE_BURST;
  m->states[CIRCPAD_STATE_BURST].
      next_state[CIRCPAD_EVENT_LENGTH_COUNT] = CIRCPAD_STATE_START;
}