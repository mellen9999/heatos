/* vos hardening of dropbear, applied on top of src/default_options.h.
 *
 * dropbear is the one listening service on vos, and vos is single-user root, so
 * an authentication bypass here is a root shell. every relaxation below the
 * default is removed, and the service only ever binds to the wireguard
 * interface (a runtime flag in init), never the untrusted LAN.
 */

/* pubkey only. a password prompt on a root-only box is a brute-force target and
 * buys nothing -- there is exactly one key that may enter, titan's, and it is
 * baked into the read-only image where verity covers it. */
#define DROPBEAR_SVR_PASSWORD_AUTH 0
#define DROPBEAR_SVR_PUBKEY_AUTH 1

/* ed25519 is the host and user key type: small, fast, no parameter choices to
 * get wrong. drop the older, larger, more error-prone families. */
#define DROPBEAR_ED25519 1
#define DROPBEAR_ECDSA 0
#define DROPBEAR_RSA 0
#define DROPBEAR_DSS 0

/* no X11 forwarding, no agent forwarding: nothing on vos needs them and each is
 * a channel an attacker on the far end could push through. local and remote TCP
 * forwarding stay on -- that is how you reach a service on the machine vos is
 * plugged into, which is part of the point. */
#define DROPBEAR_SVR_AGENTFWD 0
#define DROPBEAR_X11FWD 0
