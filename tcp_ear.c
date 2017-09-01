/* TCP EAR (ECN and RTT) congestion control.
 *
 * More information...
 *
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <net/tcp.h>
#include <linux/inet_diag.h>

#define EAR_MAX_ALPHA	1024U
#define EAR_MIN_BETA 1U
#define EAR_MIN_BETA_RTT 2000U
#define EAR_MAX_BETA 16U
#define EAR_MAX_BETA_RTT 32000U
#define RTT_THRESHOLD_ON_INIT 30000U // us
#define EAR_C 1000000U // Kbps
#define EAR_PKT_SIZE 12U // Kbits
#define EAR_RTT_DEFAULT 1000U // us
#define EAR_K (EAR_C*EAR_RTT_DEFAULT/EAR_PKT_SIZE/1000000+30) // pkts


struct ear {
	u32 acked_bytes_ecn;
	u32 acked_bytes_total;
	u16	rtt_count;		/* # of RTTs measured within last RTT */
	u32	rtt_min;		/* min of RTTs measured within last RTT (in usec) */
	u32	rtt_base;	/* the min of all RTT measurements (in usec) */
	u32 rtt_threshold;
	u32 prior_snd_una;
	u32 prior_rcv_nxt;
	u32 ear_alpha;
	u32 ear_beta;
	u32 next_seq;
	u32 ce_state;
	u32 delayed_ack_reserved;
	u32 cwr_cwnd;
	u32 loss_cwnd;
	u32 last_rtt_cwnd;
	u8 prior_ca_state;
};

static unsigned int ear_shift_g __read_mostly = 4; /* g = 1/2^4 */
module_param(ear_shift_g, uint, 0644);
MODULE_PARM_DESC(ear_shift_g, "parameter g for updating ear_alpha");

static unsigned int ear_alpha_on_init __read_mostly = EAR_MAX_ALPHA;
module_param(ear_alpha_on_init, uint, 0644);
MODULE_PARM_DESC(ear_alpha_on_init, "parameter for initial alpha value");

static unsigned int ear_rtt_enable __read_mostly = 0;
module_param(ear_rtt_enable, uint, 0644);
MODULE_PARM_DESC(ear_rtt_enable, "parameter for enabling ear rtt module");

static unsigned int ear_beta_enable __read_mostly = 0;
module_param(ear_beta_enable, uint, 0644);
MODULE_PARM_DESC(ear_beta_enable, "parameter for enabling ear beta");

static unsigned int ear_beta_on_init __read_mostly = EAR_MIN_BETA;
module_param(ear_beta_on_init, uint, 0644);
MODULE_PARM_DESC(ear_beta_on_init, "parameter for initial beta value");

static unsigned int ear_f_enable __read_mostly = 0;
module_param(ear_f_enable, uint, 0644);
MODULE_PARM_DESC(ear_f_enable, "parameter for enabling ear f tuning");

static unsigned int ear_c __read_mostly = EAR_C;
module_param(ear_c, uint, 0644);
MODULE_PARM_DESC(ear_c, "parameter for initial ear capacity C value");

static unsigned int ear_k __read_mostly = EAR_K;
module_param(ear_k, uint, 0644);
MODULE_PARM_DESC(ear_k, "parameter for initial ear K threshold value");

static unsigned int ear_rtt_threshold_on_init __read_mostly = RTT_THRESHOLD_ON_INIT;
module_param(ear_rtt_threshold_on_init, uint, 0644);
MODULE_PARM_DESC(ear_rtt_threshold_on_init, "parameter for initial rtt threshold value");

static unsigned int ear_fast_loss_recovery __read_mostly = 0;
module_param(ear_fast_loss_recovery, uint, 0644);
MODULE_PARM_DESC(ear_fast_loss_recovery, "parameter for ear fast loss recovery");

static unsigned int ear_clamp_alpha_on_loss __read_mostly;
module_param(ear_clamp_alpha_on_loss, uint, 0644);
MODULE_PARM_DESC(ear_clamp_alpha_on_loss,
		 "parameter for clamping alpha on loss");

static struct tcp_congestion_ops ear_reno;

static void ear_reset(const struct tcp_sock *tp, struct ear *ca)
{
	ca->next_seq = tp->snd_nxt;
	ca->last_rtt_cwnd = tp->snd_cwnd;
	ca->acked_bytes_ecn = 0;
	ca->acked_bytes_total = 0;
	ca->rtt_count = 0;
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

		ca->ear_alpha = min(ear_alpha_on_init, EAR_MAX_ALPHA);
		ca->ear_beta = min(ear_beta_on_init, EAR_MAX_BETA);

		ca->delayed_ack_reserved = 0;
		ca->cwr_cwnd = 0;
		ca->loss_cwnd = 0;
		ca->last_rtt_cwnd = 0x7fffffff;
		ca->ce_state = 0;
		ca->prior_ca_state = 0;
		ca->rtt_base = 0x7fffffff;
		ca->rtt_threshold = ear_rtt_threshold_on_init;

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
		u32 f = 8*ear_k*1024/(ear_c*ca->rtt_base/EAR_PKT_SIZE/1000000 + ear_k);
		return max(tp->snd_cwnd - ((tp->snd_cwnd * ca->ear_alpha * f) >> 11U), 2U);
	}
	else
		return max(tp->snd_cwnd - ((tp->snd_cwnd * ca->ear_alpha) >> 11U), 2U);
}

static u32 ear_cwnd_rtt(struct sock *sk) {
	struct ear *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 dividend = tp->snd_cwnd * (ca->rtt_min - ca->rtt_base - 
		ca->rtt_threshold) * (ca->last_rtt_cwnd-1);
	u32 divisor = ca->rtt_base * ca->last_rtt_cwnd;
	u32 cwnd_to_reduce = dividend / divisor;
	return max(tp->snd_cwnd - cwnd_to_reduce, 2U);
}

static u32 ear_ssthresh(struct sock *sk)
{
	struct ear *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	ca->cwr_cwnd = tp->snd_cwnd;
	return ear_cwnd_ecn(sk);
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

		/* alpha = (1 - g) * alpha + g * F */
		alpha -= min_not_zero(alpha, alpha >> ear_shift_g);
		if (bytes_ecn) {
			/* If ear_shift_g == 1, a 32bit value would overflow
			 * after 8 Mbytes.
			 */
			bytes_ecn <<= (10 - ear_shift_g);
			do_div(bytes_ecn, max(1U, ca->acked_bytes_total));

			alpha = min(alpha + (u32)bytes_ecn, EAR_MAX_ALPHA);
		}
		/* ear_alpha can be read from ear_get_info() without
		 * synchro, so we ask compiler to not use ear_alpha
		 * as a temporary variable in prior operations.
		 */
		WRITE_ONCE(ca->ear_alpha, alpha);

		if (ear_rtt_enable) {
			u32 cwnd_rtt = 0x7fffffff;
			if (ca->rtt_count && ca->rtt_min > (ca->rtt_base + ca->rtt_threshold))
				cwnd_rtt = ear_cwnd_rtt(sk);
			tp->snd_cwnd = min(tp->snd_cwnd, cwnd_rtt);
		}

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
	ca->rtt_count++;
}

static void ear_state(struct sock *sk, u8 new_state)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct ear *ca = inet_csk_ca(sk);
	
	if (ear_fast_loss_recovery) {
		if (new_state != ca->prior_ca_state) {
			if (new_state >= TCP_CA_Recovery && ca->prior_ca_state < TCP_CA_Recovery)
				/* Entering loss recovery; save current cwnd. */
				ca->loss_cwnd = tp->snd_cwnd;
			if (ca->prior_ca_state >= TCP_CA_Recovery && new_state < TCP_CA_Recovery)
				/* Exiting loss recovery; restore cwnd saved before recovery. */
				tp->snd_cwnd = max(tp->snd_cwnd, 
					max(ca->loss_cwnd - ((ca->loss_cwnd * ca->ear_alpha) >> 11U), 2U));
			ca->prior_ca_state = new_state;
		}
	}

	if (ear_clamp_alpha_on_loss && new_state == TCP_CA_Loss)
		/* If this extension is enabled, we clamp dctcp_alpha to
		 * max on packet loss; the motivation is that dctcp_alpha
		 * is an indicator to the extend of congestion and packet
		 * loss is an indicator of extreme congestion; setting
		 * this in practice turned out to be beneficial, and
		 * effectively assumes total congestion which reduces the
		 * window by half.
		 */
		ca->ear_alpha = EAR_MAX_ALPHA;
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

	return max(tcp_sk(sk)->snd_cwnd, ca->cwr_cwnd);
}

static void ear_cong_avoid_ai(struct tcp_sock *tp, u32 w, u32 acked, u32 step)
{
	/* If credits accumulated at a higher w, apply them gently now. */
	if (tp->snd_cwnd_cnt >= w) {
		tp->snd_cwnd_cnt = 0;
		tp->snd_cwnd += step;
	}

	tp->snd_cwnd_cnt += acked;
	if (tp->snd_cwnd_cnt >= w) {
		u32 delta = tp->snd_cwnd_cnt / w;

		tp->snd_cwnd_cnt -= delta * w;
		tp->snd_cwnd += delta*step;
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
	if (ear_beta_enable) {
		if (ca->rtt_base < EAR_MIN_BETA_RTT)
			ca->ear_beta = EAR_MIN_BETA;
		else if (ca->rtt_base > EAR_MAX_BETA_RTT)
			ca->ear_beta = EAR_MAX_BETA;
		else
			ca->ear_beta = ca->rtt_base / EAR_MAX_BETA_RTT;
		ca->ear_beta = min(ca->ear_beta, EAR_MAX_BETA);
		ca->ear_beta = max(ca->ear_beta, EAR_MIN_BETA);
	}
	ear_cong_avoid_ai(tp, tp->snd_cwnd, acked, ca->ear_beta);
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
