/* TCP EAR (ECN and RTT) congestion control.
 *
 * More information...
 *
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>

#define EAR_SCALE 1024U
#define EAR_BETA_ON_INIT 128U // scaled by EAR_SCALE
#define EAR_C_DEFAULT 1000000U // Kbps
#define EAR_PKT_SIZE_DEFAULT 12U // Kbits
#define EAR_K_DEFAULT 300U // pkts
#define EAR_RTT_THRESHOLD_HEADROOM_ON_INIT 5000U // us
#define EAR_RTT_THRESHOLD_FACTOR_ON_INIT 1024U // scaled by EAR_SCALE
#define EAR_MIN_H_RTT 3000U
#define EAR_H_FACTOR 120U // scaled by EAR_SCALE
#define EAR_MIN_H 100U // scaled by EAR_SCALE
#define EAR_MAX_H 5000U // scaled by EAR_SCALE

struct ear {
	u32 acked_bytes_ecn;
	u32 acked_bytes_total;
	u16	rtt_count;
	u32 rtt_sum;
	u32	rtt_min;
	u32	rtt_ave;
	u32	rtt_base;
	u32 prior_snd_una;
	u32 prior_rcv_nxt;
	u32 ear_alpha;
	u32 ear_h;
	u32 next_seq;
	u32 ce_state;
	u32 delayed_ack_reserved;
	u32 loss_cwnd;
	u8 prior_ca_state;
};

static unsigned int ear_shift_g __read_mostly = 4; /* g = 1/2^n */
module_param(ear_shift_g, uint, 0644);
MODULE_PARM_DESC(ear_shift_g, "parameter g for updating ear_alpha");

static unsigned int ear_alpha_on_init __read_mostly = EAR_SCALE;
module_param(ear_alpha_on_init, uint, 0644);
MODULE_PARM_DESC(ear_alpha_on_init, "parameter for initial alpha value");

static unsigned int ear_f_enable __read_mostly = 1;
module_param(ear_f_enable, uint, 0644);
MODULE_PARM_DESC(ear_f_enable, "parameter for enabling ear f tuning");

static unsigned int ear_c __read_mostly = EAR_C_DEFAULT;
module_param(ear_c, uint, 0644);
MODULE_PARM_DESC(ear_c, "parameter for link capacity value (Kbps)");

static unsigned int ear_pkt_size __read_mostly = EAR_PKT_SIZE_DEFAULT;
module_param(ear_pkt_size, uint, 0644);
MODULE_PARM_DESC(ear_pkt_size, "parameter for packet size (Kbits)");

static unsigned int ear_k __read_mostly = EAR_K_DEFAULT;
module_param(ear_k, uint, 0644);
MODULE_PARM_DESC(ear_k, "parameter for ECN marking threshold (pkts)");

static unsigned int ear_rtt_enable __read_mostly = 1;
module_param(ear_rtt_enable, uint, 0644);
MODULE_PARM_DESC(ear_rtt_enable, "parameter for enabling ear rtt module");

static unsigned int ear_beta __read_mostly = EAR_BETA_ON_INIT;
module_param(ear_beta, uint, 0644);
MODULE_PARM_DESC(ear_beta, "parameter for initial beta value (scaled by 1024)");

static unsigned int ear_rtt_threshold_headroom __read_mostly = EAR_RTT_THRESHOLD_HEADROOM_ON_INIT;
module_param(ear_rtt_threshold_headroom, uint, 0644);
MODULE_PARM_DESC(ear_rtt_threshold_headroom, "parameter for initial rtt threshold headroom (us)");

static unsigned int ear_rtt_threshold_factor __read_mostly = EAR_RTT_THRESHOLD_FACTOR_ON_INIT;
module_param(ear_rtt_threshold_factor, uint, 0644);
MODULE_PARM_DESC(ear_rtt_threshold_factor, "parameter for initial rtt threshold factor (scaled by 1024)");

static unsigned int ear_h_enable __read_mostly = 0;
module_param(ear_h_enable, uint, 0644);
MODULE_PARM_DESC(ear_h_enable, "parameter for enabling ear adaptive congestion avoidance");

static unsigned int ear_h_on_init __read_mostly = EAR_SCALE;
module_param(ear_h_on_init, uint, 0644);
MODULE_PARM_DESC(ear_h_on_init, "parameter for initial h value");

static unsigned int ear_clamp_alpha_on_loss __read_mostly;
module_param(ear_clamp_alpha_on_loss, uint, 0644);
MODULE_PARM_DESC(ear_clamp_alpha_on_loss, "parameter for clamping alpha on loss");

static struct tcp_congestion_ops ear_reno;

static void ear_reset(const struct tcp_sock *tp, struct ear *ca)
{
	ca->next_seq = tp->snd_nxt;
	ca->acked_bytes_ecn = 0;
	ca->acked_bytes_total = 0;
	ca->rtt_count = 0;
	ca->rtt_sum = 0;
	ca->rtt_min = 0x7fffffff;
}

static void ear_init(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	if ((tp->ecn_flags & TCP_ECN_OK) ||
	    (sk->sk_state == TCP_LISTEN ||
	     sk->sk_state == TCP_CLOSE)) {
		struct ear *ca = inet_csk_ca(sk);

		ca->prior_snd_una = tp->snd_una;
		ca->prior_rcv_nxt = tp->rcv_nxt;

		ca->ear_alpha = min(ear_alpha_on_init, EAR_SCALE);
		ca->ear_h = min(ear_h_on_init, EAR_MAX_H);

		ca->delayed_ack_reserved = 0;
		ca->loss_cwnd = 0;
		ca->ce_state = 0;
		ca->prior_ca_state = 0;
		ca->rtt_base = 0x7fffffff;
		ca->rtt_ave = 0;

		ear_reset(tp, ca);
		return;
	}

	/* No ECN support? Fall back to Reno. Also need to clear
	 * ECT from sk since it is set during 3WHS for ear.
	 */
	inet_csk(sk)->icsk_ca_ops = &ear_reno;
	INET_ECN_dontxmit(sk);
}

static u32 ear_cwnd_ecn(struct sock *sk) {
	struct ear *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	if (ear_f_enable && ca->rtt_base != 0x7fffffff) {
		u32 f = 8*ear_k*EAR_SCALE/(ear_c*ca->rtt_base/ear_pkt_size/1000000 + ear_k);
		u32 cwnd_reduction = (tp->snd_cwnd * (ca->ear_alpha + 64)* f) >> 21U;
		if (tp->snd_cwnd > cwnd_reduction + 2)
			return (tp->snd_cwnd - cwnd_reduction);
		else
			return 2;
	}
	else
		return max(tp->snd_cwnd - ((tp->snd_cwnd * ca->ear_alpha) >> 11U), 2U);
}

static u32 ear_cwnd_rtt(struct sock *sk) {
	//struct ear *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	return max(tp->snd_cwnd - ((tp->snd_cwnd * ear_beta) >> 10U), 2U);
}

static u32 ear_ssthresh(struct sock *sk)
{
	struct ear *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 cwnd_temp = tp->snd_cwnd;
	u32 cwnd_ecn = 0x7fffffff;
	u32 cwnd_rtt = 0x7fffffff;

	ca->loss_cwnd = tp->snd_cwnd;

	cwnd_ecn = ear_cwnd_ecn(sk);

	if (ear_rtt_enable) {
		if (ca->rtt_count && ca->rtt_min > ((ca->rtt_base*ear_rtt_threshold_factor) >> 10U) + ear_rtt_threshold_headroom)
			cwnd_rtt = ear_cwnd_rtt(sk);
	}

	cwnd_temp = min(cwnd_ecn, cwnd_rtt);
	return min(tp->snd_cwnd, cwnd_temp);
}

/* Minimal DCTCP CE state machine:
 *
 * S:	0 <- last pkt was non-CE
 *	1 <- last pkt was CE
 */

static void ear_ce_state_0_to_1(struct sock *sk)
{
	struct ear *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* State has changed from CE=0 to CE=1 and delayed
	 * ACK has not sent yet.
	 */
	if (!ca->ce_state && ca->delayed_ack_reserved) {
		u32 tmp_rcv_nxt;

		/* Save current rcv_nxt. */
		tmp_rcv_nxt = tp->rcv_nxt;

		/* Generate previous ack with CE=0. */
		tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
		tp->rcv_nxt = ca->prior_rcv_nxt;

		tcp_send_ack(sk);

		/* Recover current rcv_nxt. */
		tp->rcv_nxt = tmp_rcv_nxt;
	}

	ca->prior_rcv_nxt = tp->rcv_nxt;
	ca->ce_state = 1;

	tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
}

static void ear_ce_state_1_to_0(struct sock *sk)
{
	struct ear *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* State has changed from CE=1 to CE=0 and delayed
	 * ACK has not sent yet.
	 */
	if (ca->ce_state && ca->delayed_ack_reserved) {
		u32 tmp_rcv_nxt;

		/* Save current rcv_nxt. */
		tmp_rcv_nxt = tp->rcv_nxt;

		/* Generate previous ack with CE=1. */
		tp->ecn_flags |= TCP_ECN_DEMAND_CWR;
		tp->rcv_nxt = ca->prior_rcv_nxt;

		tcp_send_ack(sk);

		/* Recover current rcv_nxt. */
		tp->rcv_nxt = tmp_rcv_nxt;
	}

	ca->prior_rcv_nxt = tp->rcv_nxt;
	ca->ce_state = 0;

	tp->ecn_flags &= ~TCP_ECN_DEMAND_CWR;
}

static void ear_in_ack_event(struct sock *sk, u32 flags)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ear *ca = inet_csk_ca(sk);
	u32 acked_bytes = tp->snd_una - ca->prior_snd_una;

	/* If ack did not advance snd_una, count dupack as MSS size.
	 * If ack did update window, do not count it at all.
	 */
	if (acked_bytes == 0 && !(flags & CA_ACK_WIN_UPDATE))
		acked_bytes = inet_csk(sk)->icsk_ack.rcv_mss;
	if (acked_bytes) {
		ca->acked_bytes_total += acked_bytes;
		ca->prior_snd_una = tp->snd_una;

		if (flags & CA_ACK_ECE)
			ca->acked_bytes_ecn += acked_bytes;
	}

	/* Once per RTT */
	if (!before(tp->snd_una, ca->next_seq)) {
		u64 bytes_ecn = ca->acked_bytes_ecn;
		u32 alpha = ca->ear_alpha;
		u32 cwnd_temp = tp->snd_cwnd;
		u32 cwnd_ecn = 0x7fffffff;
		u32 cwnd_rtt = 0x7fffffff;

		/* alpha = (1 - g) * alpha + g * F */
		alpha -= min_not_zero(alpha, alpha >> ear_shift_g);
		if (bytes_ecn) {
			/* If ear_shift_g == 1, a 32bit value would overflow
			 * after 8 Mbytes.
			 */
			bytes_ecn <<= (10 - ear_shift_g);
			do_div(bytes_ecn, max(1U, ca->acked_bytes_total));

			alpha = min(alpha + (u32)bytes_ecn, EAR_SCALE);
		}
		/* ear_alpha can be read from ear_get_info() without
		 * synchro, so we ask compiler to not use ear_alpha
		 * as a temporary variable in prior operations.
		 */
		WRITE_ONCE(ca->ear_alpha, alpha);

		if (ca->rtt_count) {
			u32 rtt_ave = ca->rtt_sum / ca->rtt_count;
			ca->rtt_ave = ca->rtt_ave - (ca->rtt_ave >> ear_shift_g) + (rtt_ave >> ear_shift_g);
		}

		//if (bytes_ecn)
			//cwnd_ecn = ear_cwnd_ecn(sk);

		if (ear_rtt_enable) {
			if (ca->rtt_count && ca->rtt_min > ((ca->rtt_base*ear_rtt_threshold_factor) >> 10U) + ear_rtt_threshold_headroom)
				cwnd_rtt = ear_cwnd_rtt(sk);
		}

		cwnd_temp = min(cwnd_ecn, cwnd_rtt);
		tp->snd_cwnd = min(tp->snd_cwnd, cwnd_temp);

		ear_reset(tp, ca);
	}
}

static void ear_pkts_acked(struct sock *sk, const struct ack_sample *sample)
{
	struct ear *ca = inet_csk_ca(sk);

	u32 vrtt;

	if (sample->rtt_us < 0)
		return;

	/* Never allow zero rtt or rtt_base */
	vrtt = sample->rtt_us + 1;

	/* Filter to find propagation delay: */
	if (vrtt < ca->rtt_base)
		ca->rtt_base = vrtt;

	/* Find the min RTT during the last RTT to find
	 * the current prop. delay + queuing delay:
	 */
	ca->rtt_min = min(ca->rtt_min, vrtt);
	ca->rtt_sum += vrtt;
	ca->rtt_count++;
}

static void ear_state(struct sock *sk, u8 new_state)
{
	struct ear *ca = inet_csk_ca(sk);

	if (ear_clamp_alpha_on_loss && new_state == TCP_CA_Loss)
		/* If this extension is enabled, we clamp dctcp_alpha to
		 * max on packet loss; the motivation is that dctcp_alpha
		 * is an indicator to the extend of congestion and packet
		 * loss is an indicator of extreme congestion; setting
		 * this in practice turned out to be beneficial, and
		 * effectively assumes total congestion which reduces the
		 * window by half.
		 */
		ca->ear_alpha = EAR_SCALE;

	ca->prior_ca_state = new_state;
}

static void ear_update_ack_reserved(struct sock *sk, enum tcp_ca_event ev)
{
	struct ear *ca = inet_csk_ca(sk);

	switch (ev) {
	case CA_EVENT_DELAYED_ACK:
		if (!ca->delayed_ack_reserved)
			ca->delayed_ack_reserved = 1;
		break;
	case CA_EVENT_NON_DELAYED_ACK:
		if (ca->delayed_ack_reserved)
			ca->delayed_ack_reserved = 0;
		break;
	default:
		/* Don't care for the rest. */
		break;
	}
}

static void ear_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
	switch (ev) {
	case CA_EVENT_ECN_IS_CE:
		ear_ce_state_0_to_1(sk);
		break;
	case CA_EVENT_ECN_NO_CE:
		ear_ce_state_1_to_0(sk);
		break;
	case CA_EVENT_DELAYED_ACK:
	case CA_EVENT_NON_DELAYED_ACK:
		ear_update_ack_reserved(sk, ev);
		break;
	default:
		/* Don't care for the rest. */
		break;
	}
}

static size_t ear_get_info(struct sock *sk, u32 ext, int *attr,
			     union tcp_cc_info *info)
{
	const struct ear *ca = inet_csk_ca(sk);

	/* Fill it also in case of VEGASINFO due to req struct limits.
	 * We can still correctly retrieve it later.
	 */
	if (ext & (1 << (INET_DIAG_EARINFO - 1)) ||
	    ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		memset(&info->ear, 0, sizeof(info->ear));
		if (inet_csk(sk)->icsk_ca_ops != &ear_reno) {
			info->ear.ear_enabled = 1;
			info->ear.ear_ce_state = (u16) ca->ce_state;
			info->ear.ear_alpha = ca->ear_alpha;
			info->ear.ear_ab_ecn = ca->acked_bytes_ecn;
			info->ear.ear_ab_tot = ca->acked_bytes_total;
		}

		*attr = INET_DIAG_EARINFO;
		return sizeof(info->ear);
	}
	return 0;
}

static u32 ear_cwnd_undo(struct sock *sk)
{
	const struct ear *ca = inet_csk_ca(sk);

	return max(tcp_sk(sk)->snd_cwnd, ca->loss_cwnd);
}

static void ear_cong_avoid_ai(struct tcp_sock *tp, u32 w, u32 acked, u32 step)
{
	/* If credits accumulated at a higher w, apply them gently now. */
	w = max(w * EAR_SCALE / step, 1U);
	if (tp->snd_cwnd_cnt >= w) {
		tp->snd_cwnd_cnt = 0;
		tp->snd_cwnd += 1;
	}

	tp->snd_cwnd_cnt += acked;
	if (tp->snd_cwnd_cnt >= w) {
		u32 delta = tp->snd_cwnd_cnt / w;

		tp->snd_cwnd_cnt -= delta * w;
		tp->snd_cwnd += delta;
	}
	tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_cwnd_clamp);
}

static void ear_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ear *ca = inet_csk_ca(sk);

	if (!tcp_is_cwnd_limited(sk))
		return;

	/* In "safe" area, increase. */
	if (tcp_in_slow_start(tp)) {
		acked = tcp_slow_start(tp, acked);
		if (!acked)
			return;
	}
	/* In dangerous area, increase slowly. */
	if (ear_h_enable && ca->rtt_ave) {
		if (ca->rtt_ave < EAR_MIN_H_RTT)
			ca->ear_h = EAR_MIN_H;
		else
			ca->ear_h = (ca->rtt_ave - EAR_MIN_H_RTT)*EAR_H_FACTOR/EAR_SCALE + EAR_MIN_H;
		ca->ear_h = min(ca->ear_h, EAR_MAX_H);
		ca->ear_h = max(ca->ear_h, EAR_MIN_H);
	}
	else
		ca->ear_h = EAR_SCALE;
	ear_cong_avoid_ai(tp, tp->snd_cwnd, acked, ca->ear_h);
}

static struct tcp_congestion_ops ear __read_mostly = {
	.init		= ear_init,
	.in_ack_event   = ear_in_ack_event,
	.pkts_acked = ear_pkts_acked,
	.cwnd_event	= ear_cwnd_event,
	.ssthresh	= ear_ssthresh,
	.cong_avoid	= ear_cong_avoid,
	.undo_cwnd	= ear_cwnd_undo,
	.set_state	= ear_state,
	.get_info	= ear_get_info,
	.flags		= TCP_CONG_NEEDS_ECN,
	.owner		= THIS_MODULE,
	.name		= "ear",
};

static struct tcp_congestion_ops ear_reno __read_mostly = {
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.get_info	= ear_get_info,
	.owner		= THIS_MODULE,
	.name		= "ear-reno",
};

static int __init ear_register(void)
{
	BUILD_BUG_ON(sizeof(struct ear) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&ear);
}

static void __exit ear_unregister(void)
{
	tcp_unregister_congestion_control(&ear);
}

module_init(ear_register);
module_exit(ear_unregister);

MODULE_AUTHOR("Gaoxiong Zeng <gzengaa@cse.ust.hk>");

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("TCP EAR");
