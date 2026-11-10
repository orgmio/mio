package bbr

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"

	"github.com/orgmio/mio/internal/congestion/common"
)

// BbrSender 实现 BBR 拥塞控制算法。BBR 旨在估算当前可用的瓶颈带宽和 RTT（名称由此而来），
// 并依据这些信号调节 pacing 速率和拥塞窗口大小。
//
// BBR 依赖 pacing 才能正常工作。禁用 pacing 时不要使用 BBR。
//

const (
	minBps = 65536 // 64 KB/s

	invalidPacketNumber            = -1
	initialCongestionWindowPackets = 32
	minCongestionWindowPackets     = 4

	debugEnv = "HYSTERIA_BBR_DEBUG"
)

// PROBE_BW 阶段使用的增益循环。
var pacingGain = [...]float64{1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0}

const (
	// 增益循环的长度。
	gainCycleLength = len(pacingGain)
	// 带宽滤波器窗口大小，以往返次数计。
	bandwidthWindowSize = gainCycleLength + 2

	// 当前 min_rtt 值的过期时间。
	minRttExpiry = 10 * time.Second
	// 连接处于 PROBE_RTT 模式的最短时间。
	probeRttTime = 200 * time.Millisecond
	// 连续多个往返的带宽增长不足此比例时，连接退出 STARTUP 模式。
	startupGrowthTarget = 1.25

	// 标志。
	defaultStartupFullLossCount  = 8
	quicBbr2DefaultLossThreshold = 0.02
)

type bbrMode int

const (
	// 连接的启动阶段。
	bbrModeStartup = iota
	// 在启动阶段达到可能的最高带宽后，降低 pacing 速率以排空队列。
	bbrModeDrain
	// 巡航模式。
	bbrModeProbeBw
	// 临时降低发送速率，以清空缓冲区并测量真实的最小 RTT。
	bbrModeProbeRtt
)

type bbrSender struct {
	rttStats congestion.RTTStatsProvider
	clock    Clock
	pacer    *common.Pacer

	mode bbrMode

	// 带宽采样器向 BBR 提供各个时点的带宽测量值。
	sampler *bandwidthSampler

	// 连接期间已发生的往返次数。
	roundTripCount roundTripCount

	// 最近发送的数据包编号。
	lastSentPacket congestion.PacketNumber
	// 确认 |current_round_trip_end_| 之后的任意数据包时，往返计数器都会递增。
	currentRoundTripEnd congestion.PacketNumber

	// 当前轮次中发生丢包的拥塞事件数。
	numLossEventsInRound uint64

	// 当前轮次中丢失的总字节数。
	bytesLostInRound congestion.ByteCount

	// 跟踪最近多个往返期间最大带宽的滤波器。
	maxBandwidth *WindowedFilter[Bandwidth, roundTripCount]

	// 最小 RTT 估计值。如果 10 秒内没有采集到新值，该值将自动过期并触发 PROBE_RTT 模式。
	minRtt time.Duration
	// 当前 |min_rtt_| 值的赋值时间。
	minRttTimestamp monotime.Time

	// 允许的最大在途字节数。
	congestionWindow congestion.ByteCount

	// |congestion_window_| 的初始值。
	initialCongestionWindow congestion.ByteCount

	// |congestion_window_| 可达到的最大值。
	maxCongestionWindow congestion.ByteCount

	// |congestion_window_| 可达到的最小值。
	minCongestionWindow congestion.ByteCount

	// STARTUP 阶段使用的 pacing 增益。
	highGain float64

	// STARTUP 阶段使用的 CWND 增益。
	highCwndGain float64

	// DRAIN 阶段使用的 pacing 增益。
	drainGain float64

	// 连接当前的 pacing 速率。
	pacingRate Bandwidth

	// 当前应用于 pacing 速率的增益。
	pacingGain float64
	// 当前应用于拥塞窗口的增益。
	congestionWindowGain float64

	// PROBE_BW 期间拥塞窗口使用的增益，从 quic_bbr_cwnd_gain 标志锁存。
	congestionWindowGainConstant float64
	// 保持在 STARTUP 模式的 RTT 数，默认为 3。
	numStartupRtts int64

	// PROBE_BW 模式下的往返次数，用于确定当前 pacing 增益循环。
	cycleCurrentOffset int
	// 上一次 pacing 增益循环的开始时间。
	lastCycleStart monotime.Time

	// 指示连接是否已达到满带宽模式。
	isAtFullBandwidth bool
	// 带宽没有显著增长的轮次数。
	roundsWithoutBandwidthGain int64
	// 用于比较增长幅度的带宽值。
	bandwidthAtLastRound Bandwidth

	// 退出静默状态时设为 true。
	exitingQuiescence bool

	// 退出 PROBE_RTT 的时间。设为零表示退出时间尚未确定，因为在途数据包数还未达到所需值。
	exitProbeRttAt monotime.Time
	// 指示自 PROBE_RTT 激活以来是否已经过一个往返。
	probeRttRoundPassed bool

	// 指示最近的带宽样本是否标记为 app-limited。
	lastSampleIsAppLimited bool
	// 指示是否记录过任何非 app-limited 样本。
	hasNoAppLimitedSample bool

	// 当前恢复状态。
	recoveryState bbrRecoveryState
	// 收到 |end_recovery_at_| 之后数据包的确认时，BBR 将退出恢复模式。大于零的值表示至少检测到一次丢包，
	// 因此不得将其重置为零。
	endRecoveryAt congestion.PacketNumber
	// 丢包恢复期间用于限制在途字节数的窗口。
	recoveryWindow congestion.ByteCount
	// 如果为 true，则将恢复期间的所有样本视为 app-limited。
	isAppLimitedRecovery bool // 未使用

	// 为 true 时，以 1.5 倍速率进行 pacing，并在 STARTUP 中禁用 packet conservation。
	slowerStartup bool // 未使用
	// 为 true 时，在 STARTUP 中禁用 packet conservation。
	rateBasedStartup bool // 未使用

	// 为 true 时，在 STARTUP 期间加入最近一次 ack 聚合测量值。
	enableAckAggregationDuringStartup bool
	// 为 true 时，若带宽增长超过 25%，则在 STARTUP 期间使窗口化 ack 聚合值过期。
	expireAckAggregationInStartup bool

	// 为 true 时，只有在 bytes_in_flight 降至 BDP 以下或需要进入高增益模式时，才退出低增益模式。
	drainToTarget bool

	// 为 true 时，在 STARTUP 检测到超调后降低 pacing 速率。
	detectOvershooting bool
	// detect_overshooting_ 为 true 期间丢失的字节数。
	bytesLostWhileDetectingOvershooting congestion.ByteCount
	// 如果 bytes_lost_while_detecting_overshooting_ *
	// bytes_lost_multiplier_while_detecting_overshooting_ > IW，则降低 pacing 速率。
	bytesLostMultiplierWhileDetectingOvershooting uint8
	// 检测到超调时，pacing_rate_ 不得降至此值 / min_rtt 以下。
	cwndToCalculateMinPacingRate congestion.ByteCount

	// 调整网络参数时的最大拥塞窗口。
	maxCongestionWindowWithNetworkParametersAdjusted congestion.ByteCount // 未使用

	// 参数。
	maxDatagramSize congestion.ByteCount
	// 在发送数据包时记录；等价于 |unacked_packets_->bytes_in_flight()|。
	bytesInFlight congestion.ByteCount

	debug bool
}

var _ congestion.CongestionControl = &bbrSender{}

func NewBbrSender(
	clock Clock,
	initialMaxDatagramSize congestion.ByteCount,
) *bbrSender {
	return newBbrSender(
		clock,
		initialMaxDatagramSize,
		initialCongestionWindowPackets*initialMaxDatagramSize,
		congestion.MaxCongestionWindowPackets*initialMaxDatagramSize,
	)
}

func newBbrSender(
	clock Clock,
	initialMaxDatagramSize,
	initialCongestionWindow,
	initialMaxCongestionWindow congestion.ByteCount,
) *bbrSender {
	debug, _ := strconv.ParseBool(os.Getenv(debugEnv))
	b := &bbrSender{
		clock:                        clock,
		mode:                         bbrModeStartup,
		sampler:                      newBandwidthSampler(roundTripCount(bandwidthWindowSize)),
		lastSentPacket:               invalidPacketNumber,
		currentRoundTripEnd:          invalidPacketNumber,
		maxBandwidth:                 NewWindowedFilter(roundTripCount(bandwidthWindowSize), MaxFilter[Bandwidth]),
		congestionWindow:             initialCongestionWindow,
		initialCongestionWindow:      initialCongestionWindow,
		maxCongestionWindow:          initialMaxCongestionWindow,
		minCongestionWindow:          minCongestionWindowForMaxDatagramSize(initialMaxDatagramSize),
		highGain:                     3.0,
		highCwndGain:                 2.25,
		drainGain:                    1.0 / 3.0,
		pacingGain:                   1.0,
		congestionWindowGain:         1.0,
		congestionWindowGainConstant: 2.5,
		numStartupRtts:               4,
		recoveryState:                bbrRecoveryStateNotInRecovery,
		endRecoveryAt:                invalidPacketNumber,
		recoveryWindow:               initialMaxCongestionWindow,
		bytesLostMultiplierWhileDetectingOvershooting:    2,
		enableAckAggregationDuringStartup:                true,
		expireAckAggregationInStartup:                    true,
		cwndToCalculateMinPacingRate:                     initialCongestionWindow,
		maxCongestionWindowWithNetworkParametersAdjusted: initialMaxCongestionWindow,
		maxDatagramSize:                                  initialMaxDatagramSize,
		debug:                                            debug,
	}
	b.pacer = common.NewPacer(b.bandwidthForPacer)
	if b.debug {
		b.debugPrint("BBR mode: aggressive")
	}

	b.enterStartupMode(b.clock.Now())

	return b
}
func minCongestionWindowForMaxDatagramSize(maxDatagramSize congestion.ByteCount) congestion.ByteCount {
	return minCongestionWindowPackets * maxDatagramSize
}

func scaleByteWindowForDatagramSize(window, oldMaxDatagramSize, newMaxDatagramSize congestion.ByteCount) congestion.ByteCount {
	if oldMaxDatagramSize == newMaxDatagramSize {
		return window
	}
	return congestion.ByteCount(uint64(window) * uint64(newMaxDatagramSize) / uint64(oldMaxDatagramSize))
}

func (b *bbrSender) rescalePacketSizedWindows(maxDatagramSize congestion.ByteCount) {
	oldMaxDatagramSize := b.maxDatagramSize
	b.maxDatagramSize = maxDatagramSize
	b.initialCongestionWindow = scaleByteWindowForDatagramSize(b.initialCongestionWindow, oldMaxDatagramSize, maxDatagramSize)
	b.maxCongestionWindow = scaleByteWindowForDatagramSize(b.maxCongestionWindow, oldMaxDatagramSize, maxDatagramSize)
	b.minCongestionWindow = minCongestionWindowForMaxDatagramSize(maxDatagramSize)
	b.cwndToCalculateMinPacingRate = scaleByteWindowForDatagramSize(b.cwndToCalculateMinPacingRate, oldMaxDatagramSize, maxDatagramSize)
	b.maxCongestionWindowWithNetworkParametersAdjusted = scaleByteWindowForDatagramSize(
		b.maxCongestionWindowWithNetworkParametersAdjusted,
		oldMaxDatagramSize,
		maxDatagramSize,
	)
}

func (b *bbrSender) SetRTTStatsProvider(provider congestion.RTTStatsProvider) {
	b.rttStats = provider
}

// TimeUntilSend 实现 SendAlgorithm 接口。
func (b *bbrSender) TimeUntilSend(bytesInFlight congestion.ByteCount) monotime.Time {
	return b.pacer.TimeUntilSend()
}

// HasPacingBudget 实现 SendAlgorithm 接口。
func (b *bbrSender) HasPacingBudget(now monotime.Time) bool {
	return b.pacer.Budget(now) >= b.maxDatagramSize
}

// OnPacketSent 实现 SendAlgorithm 接口。
func (b *bbrSender) OnPacketSent(
	sentTime monotime.Time,
	bytesInFlight congestion.ByteCount,
	packetNumber congestion.PacketNumber,
	bytes congestion.ByteCount,
	isRetransmittable bool,
) {
	b.pacer.SentPacket(sentTime, bytes)

	b.lastSentPacket = packetNumber
	b.bytesInFlight = bytesInFlight

	if bytesInFlight == 0 {
		b.exitingQuiescence = true
	}

	b.sampler.OnPacketSent(sentTime, packetNumber, bytes, bytesInFlight, isRetransmittable)
}

// CanSend 实现 SendAlgorithm 接口。
func (b *bbrSender) CanSend(bytesInFlight congestion.ByteCount) bool {
	return bytesInFlight < b.GetCongestionWindow()
}

// MaybeExitSlowStart 实现 SendAlgorithm 接口。
func (b *bbrSender) MaybeExitSlowStart() {
	// 不执行任何操作。
}

// OnPacketAcked 实现 SendAlgorithm 接口。
func (b *bbrSender) OnPacketAcked(number congestion.PacketNumber, ackedBytes, priorInFlight congestion.ByteCount, eventTime monotime.Time) {
	// 不执行任何操作。
}

// OnPacketLost 实现 SendAlgorithm 接口。
func (b *bbrSender) OnPacketLost(number congestion.PacketNumber, lostBytes, priorInFlight congestion.ByteCount) {
	// 不执行任何操作。
}

// OnRetransmissionTimeout 实现 SendAlgorithm 接口。
func (b *bbrSender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	// 不执行任何操作。
}

// SetMaxDatagramSize 实现 SendAlgorithm 接口。
func (b *bbrSender) SetMaxDatagramSize(s congestion.ByteCount) {
	if b.debug {
		b.debugPrint("Max Datagram Size: %d", s)
	}
	if s < b.maxDatagramSize {
		panic(fmt.Sprintf("congestion BUG: decreased max datagram size from %d to %d", b.maxDatagramSize, s))
	}
	oldMinCongestionWindow := b.minCongestionWindow
	oldInitialCongestionWindow := b.initialCongestionWindow
	b.rescalePacketSizedWindows(s)
	switch b.congestionWindow {
	case oldMinCongestionWindow:
		b.congestionWindow = b.minCongestionWindow
	case oldInitialCongestionWindow:
		b.congestionWindow = b.initialCongestionWindow
	default:
		b.congestionWindow = min(b.maxCongestionWindow, max(b.congestionWindow, b.minCongestionWindow))
	}
	b.recoveryWindow = min(b.maxCongestionWindow, max(b.recoveryWindow, b.minCongestionWindow))
	b.pacer.SetMaxDatagramSize(s)
}

// InSlowStart 实现 SendAlgorithmWithDebugInfos 接口。
func (b *bbrSender) InSlowStart() bool {
	return b.mode == bbrModeStartup
}

// InRecovery 实现 SendAlgorithmWithDebugInfos 接口。
func (b *bbrSender) InRecovery() bool {
	return b.recoveryState != bbrRecoveryStateNotInRecovery
}

// GetCongestionWindow 实现 SendAlgorithmWithDebugInfos 接口。
func (b *bbrSender) GetCongestionWindow() congestion.ByteCount {
	if b.mode == bbrModeProbeRtt {
		return b.probeRttCongestionWindow()
	}

	if b.InRecovery() {
		return min(b.congestionWindow, b.recoveryWindow)
	}

	return b.congestionWindow
}

func (b *bbrSender) OnCongestionEvent(number congestion.PacketNumber, lostBytes, priorInFlight congestion.ByteCount) {
	// 不执行任何操作。
}

func (b *bbrSender) OnCongestionEventEx(priorInFlight congestion.ByteCount, eventTime monotime.Time, ackedPackets []congestion.AckedPacketInfo, lostPackets []congestion.LostPacketInfo) {
	totalBytesAckedBefore := b.sampler.TotalBytesAcked()
	totalBytesLostBefore := b.sampler.TotalBytesLost()

	var isRoundStart, minRttExpired bool
	var excessAcked, bytesLost congestion.ByteCount

	// acked_packets 中最大数据包的发送状态；如果 acked_packets 为空，则取 lost_packets 中最大数据包的发送状态。
	var lastPacketSendState sendTimeState

	b.maybeAppLimited(priorInFlight)

	// 更新 bytesInFlight。
	b.bytesInFlight = priorInFlight
	for _, p := range ackedPackets {
		b.bytesInFlight -= p.BytesAcked
	}
	for _, p := range lostPackets {
		b.bytesInFlight -= p.BytesLost
	}

	if len(ackedPackets) != 0 {
		lastAckedPacket := ackedPackets[len(ackedPackets)-1].PacketNumber
		isRoundStart = b.updateRoundTripCounter(lastAckedPacket)
		b.updateRecoveryState(lastAckedPacket, len(lostPackets) != 0, isRoundStart)
	}

	sample := b.sampler.OnCongestionEvent(eventTime,
		ackedPackets, lostPackets, b.maxBandwidth.GetBest(), infBandwidth, b.roundTripCount)
	if sample.lastPacketSendState.isValid {
		b.lastSampleIsAppLimited = sample.lastPacketSendState.isAppLimited
		b.hasNoAppLimitedSample = b.hasNoAppLimitedSample || !b.lastSampleIsAppLimited
	}
	// 以下情况不更新 |max_bandwidth_|：a) 这是仅丢包事件；或 b) |acked_packets| 中所有数据包都未产生有效样本
	// （例如，仅确认 ack-only 数据包）。这两种情况下，sampler_.total_bytes_acked() 都不会变化。
	if totalBytesAckedBefore != b.sampler.TotalBytesAcked() {
		if !sample.sampleIsAppLimited || sample.sampleMaxBandwidth > b.maxBandwidth.GetBest() {
			b.maxBandwidth.Update(sample.sampleMaxBandwidth, b.roundTripCount)
		}
	}

	if sample.sampleRtt != infRTT {
		minRttExpired = b.maybeUpdateMinRtt(eventTime, sample.sampleRtt)
	}
	bytesLost = b.sampler.TotalBytesLost() - totalBytesLostBefore

	excessAcked = sample.extraAcked
	lastPacketSendState = sample.lastPacketSendState

	if len(lostPackets) != 0 {
		b.numLossEventsInRound++
		b.bytesLostInRound += bytesLost
	}

	// 处理 PROBE_BW 模式专属逻辑。
	if b.mode == bbrModeProbeBw {
		b.updateGainCyclePhase(eventTime, priorInFlight, len(lostPackets) != 0)
	}

	// 处理 STARTUP 和 DRAIN 模式专属逻辑。
	if isRoundStart && !b.isAtFullBandwidth {
		b.checkIfFullBandwidthReached(&lastPacketSendState)
	}

	b.maybeExitStartupOrDrain(eventTime)

	// 处理 PROBE_RTT 专属逻辑。
	b.maybeEnterOrExitProbeRtt(eventTime, isRoundStart, minRttExpired)

	// 计算已确认和丢失的数据包数量。
	bytesAcked := b.sampler.TotalBytesAcked() - totalBytesAckedBefore

	// 更新模型后，重新计算 pacing 速率和拥塞窗口。
	b.calculatePacingRate(bytesLost)
	b.calculateCongestionWindow(bytesAcked, excessAcked)
	b.calculateRecoveryWindow(bytesAcked, bytesLost)

	// 清理内部状态。
	// 在这里从带宽采样器中清理已过时（已确认或丢失）的数据包。
	// “least unacked” 实际上应为 FirstOutstanding，但由于 OnCongestionEventEx 没有传递该值，
	// 目前只能根据已确认/丢失的数据包进行估算。由于快速重传的存在，两者相差应不超过 2 个数据包。
	// （此行为由 quic-go 的 sentPacketHandler 中的 packetThreshold 控制。）
	var leastUnacked congestion.PacketNumber
	if len(ackedPackets) != 0 {
		leastUnacked = ackedPackets[len(ackedPackets)-1].PacketNumber - 2
	} else {
		leastUnacked = lostPackets[len(lostPackets)-1].PacketNumber + 1
	}
	b.sampler.RemoveObsoletePackets(leastUnacked)

	if isRoundStart {
		b.numLossEventsInRound = 0
		b.bytesLostInRound = 0
	}
}

func (b *bbrSender) PacingRate() Bandwidth {
	if b.pacingRate == 0 {
		return Bandwidth(b.highGain * float64(
			BandwidthFromDelta(b.initialCongestionWindow, b.getMinRtt()),
		))
	}

	return b.pacingRate
}

// 设置 STARTUP 使用的 CWND 增益，必须大于 1。
func (b *bbrSender) setHighCwndGain(highCwndGain float64) {
	b.highCwndGain = highCwndGain
	if b.mode == bbrModeStartup {
		b.congestionWindowGain = highCwndGain
	}
}

// 获取当前带宽估计值。注意，Bandwidth 的单位是 bits per second。
func (b *bbrSender) bandwidthEstimate() Bandwidth {
	return b.maxBandwidth.GetBest()
}

func (b *bbrSender) bandwidthForPacer() congestion.ByteCount {
	bps := congestion.ByteCount(float64(b.PacingRate()) / float64(BytesPerSecond))
	if bps < minBps {
		// 必须确保 pacer 使用的带宽值不为零；否则会进入一种边界情况：HasPacingBudget = false，
		// 但 TimeUntilSend 返回的时间却已到，导致 quic-go 发送循环异常并卡住。
		return minBps
	}
	return bps
}

// 返回连接当前的 RTT 估计值。除边界情况外，该值就是最小 RTT。
func (b *bbrSender) getMinRtt() time.Duration {
	if b.minRtt != 0 {
		return b.minRtt
	}
	// 如果握手数据包被废弃后又得到确认，min_rtt 仍可能有值。这只可能发生在不丢弃密钥的 QUIC 加密场景中。
	minRtt := b.rttStats.MinRTT()
	if minRtt == 0 {
		return 100 * time.Millisecond
	} else {
		return minRtt
	}
}

// 使用指定的增益计算目标拥塞窗口。
func (b *bbrSender) getTargetCongestionWindow(gain float64) congestion.ByteCount {
	bdp := bdpFromRttAndBandwidth(b.getMinRtt(), b.bandwidthEstimate())
	congestionWindow := congestion.ByteCount(gain * float64(bdp))

	// 如果尚无带宽样本，BDP 估计值将为零。
	if congestionWindow == 0 {
		congestionWindow = congestion.ByteCount(gain * float64(b.initialCongestionWindow))
	}

	return max(congestionWindow, b.minCongestionWindow)
}

// PROBE_RTT 期间的目标拥塞窗口。
func (b *bbrSender) probeRttCongestionWindow() congestion.ByteCount {
	return b.minCongestionWindow
}

func (b *bbrSender) maybeUpdateMinRtt(now monotime.Time, sampleMinRtt time.Duration) bool {
	// 如果从未得到过 min_rtt，则不要使其过期。
	minRttExpired := b.minRtt != 0 && now.After(b.minRttTimestamp.Add(minRttExpiry))
	if minRttExpired || sampleMinRtt < b.minRtt || b.minRtt == 0 {
		b.minRtt = sampleMinRtt
		b.minRttTimestamp = now
	}

	return minRttExpired
}

// 进入 STARTUP 模式。
func (b *bbrSender) enterStartupMode(now monotime.Time) {
	b.mode = bbrModeStartup
	// b.maybeTraceStateChange(logging.CongestionStateStartup)
	b.pacingGain = b.highGain
	b.congestionWindowGain = b.highCwndGain

	if b.debug {
		b.debugPrint("Phase: STARTUP")
	}
}

// 进入 PROBE_BW 模式。
func (b *bbrSender) enterProbeBandwidthMode(now monotime.Time) {
	b.mode = bbrModeProbeBw
	// b.maybeTraceStateChange(logging.CongestionStateProbeBw)
	b.congestionWindowGain = b.congestionWindowGainConstant

	// 从 {0, 2..7} 范围内为增益循环随机选择一个偏移。排除 1 是因为此时增益增加和增益降低阶段不会相邻。
	b.cycleCurrentOffset = int(rand.Int31n(congestion.PacketsPerConnectionID)) % (gainCycleLength - 1)
	if b.cycleCurrentOffset >= 1 {
		b.cycleCurrentOffset += 1
	}

	b.lastCycleStart = now
	b.pacingGain = pacingGain[b.cycleCurrentOffset]

	if b.debug {
		b.debugPrint("Phase: PROBE_BW")
	}
}

// 如果已过去一个往返，则更新往返计数器；若计数器已递增，则返回 true。
func (b *bbrSender) updateRoundTripCounter(lastAckedPacket congestion.PacketNumber) bool {
	if b.currentRoundTripEnd == invalidPacketNumber || lastAckedPacket > b.currentRoundTripEnd {
		b.roundTripCount++
		b.currentRoundTripEnd = b.lastSentPacket
		return true
	}
	return false
}

// 更新 PROBE_BW 模式当前使用的增益。
func (b *bbrSender) updateGainCyclePhase(now monotime.Time, priorInFlight congestion.ByteCount, hasLosses bool) {
	// 通常经过一个 RTT 后会推进循环。
	shouldAdvanceGainCycling := now.After(b.lastCycleStart.Add(b.getMinRtt()))
	// 如果 pacing 增益大于 1.0，连接会尝试增加在途字节数至至少 pacing_gain * BDP，以探测带宽。
	// 只要没有丢包表明缓冲区无法容纳这么多数据，就确保实际达到该目标。
	if b.pacingGain > 1.0 && !hasLosses && priorInFlight < b.getTargetCongestionWindow(b.pacingGain) {
		shouldAdvanceGainCycling = false
	}

	// 如果 pacing 增益小于 1.0，连接会尝试排空此前探测可能产生的额外队列。
	// 如果在途字节数提前降至估计的 BDP 值，则认为队列已成功排空并提前结束本轮循环。
	if b.pacingGain < 1.0 && b.bytesInFlight <= b.getTargetCongestionWindow(1) {
		shouldAdvanceGainCycling = true
	}

	if shouldAdvanceGainCycling {
		b.cycleCurrentOffset = (b.cycleCurrentOffset + 1) % gainCycleLength
		b.lastCycleStart = now
		// 保持低增益模式，直到达到目标 BDP。
		// 达到目标 BDP 后立即退出低增益模式。
		if b.drainToTarget && b.pacingGain < 1 &&
			pacingGain[b.cycleCurrentOffset] == 1 &&
			b.bytesInFlight > b.getTargetCongestionWindow(1) {
			return
		}
		b.pacingGain = pacingGain[b.cycleCurrentOffset]
	}
}

// 跟踪带宽未显著增长的往返次数。
func (b *bbrSender) checkIfFullBandwidthReached(lastPacketSendState *sendTimeState) {
	if b.lastSampleIsAppLimited {
		return
	}

	target := Bandwidth(float64(b.bandwidthAtLastRound) * startupGrowthTarget)
	if b.bandwidthEstimate() >= target {
		b.bandwidthAtLastRound = b.bandwidthEstimate()
		b.roundsWithoutBandwidthGain = 0
		if b.expireAckAggregationInStartup {
			// 带宽增长后，使旧的额外交付量测量值过期。
			b.sampler.ResetMaxAckHeightTracker(0, b.roundTripCount)
		}
		return
	}

	b.roundsWithoutBandwidthGain++
	if b.roundsWithoutBandwidthGain >= b.numStartupRtts ||
		b.shouldExitStartupDueToLoss(lastPacketSendState) {
		b.isAtFullBandwidth = true
	}
}

func (b *bbrSender) maybeAppLimited(bytesInFlight congestion.ByteCount) {
	if bytesInFlight < b.getTargetCongestionWindow(1) {
		b.sampler.OnAppLimited()
	}
}

// 在适当时从 STARTUP 转换到 DRAIN，并从 DRAIN 转换到 PROBE_BW。
func (b *bbrSender) maybeExitStartupOrDrain(now monotime.Time) {
	if b.mode == bbrModeStartup && b.isAtFullBandwidth {
		b.mode = bbrModeDrain
		// b.maybeTraceStateChange(logging.CongestionStateDrain)
		b.pacingGain = b.drainGain
		b.congestionWindowGain = b.highCwndGain

		if b.debug {
			b.debugPrint("Phase: DRAIN")
		}
	}
	if b.mode == bbrModeDrain && b.bytesInFlight <= b.getTargetCongestionWindow(1) {
		b.enterProbeBandwidthMode(now)
	}
}

// 决定是否进入或退出 PROBE_RTT。
func (b *bbrSender) maybeEnterOrExitProbeRtt(now monotime.Time, isRoundStart, minRttExpired bool) {
	if minRttExpired && !b.exitingQuiescence && b.mode != bbrModeProbeRtt {
		b.mode = bbrModeProbeRtt
		// b.maybeTraceStateChange(logging.CongestionStateProbRtt)
		b.pacingGain = 1.0
		// 在 |bytes_in_flight| 达到目标小值之前，不要确定退出 PROBE_RTT 的时间。
		b.exitProbeRttAt = 0

		if b.debug {
			b.debugPrint("BandwidthEstimate: %s, CongestionWindowGain: %.2f, PacingGain: %.2f, PacingRate: %s",
				formatSpeed(b.bandwidthEstimate()), b.congestionWindowGain, b.pacingGain, formatSpeed(b.PacingRate()))
			b.debugPrint("Phase: PROBE_RTT")
		}
	}

	if b.mode == bbrModeProbeRtt {
		b.sampler.OnAppLimited()
		// b.maybeTraceStateChange(logging.CongestionStateApplicationLimited)

		if b.exitProbeRttAt.IsZero() {
			// 如果窗口已达到合适大小，则安排退出 PROBE_RTT。PROBE_RTT 期间的 CWND 为
			// kMinimumCongestionWindow，但由于 QUIC 在发送数据包前检查 CWND，因此允许多一个数据包。
			if b.bytesInFlight < b.probeRttCongestionWindow()+congestion.MaxPacketBufferSize {
				b.exitProbeRttAt = now.Add(probeRttTime)
				b.probeRttRoundPassed = false
			}
		} else {
			if isRoundStart {
				b.probeRttRoundPassed = true
			}
			if now.Sub(b.exitProbeRttAt) >= 0 && b.probeRttRoundPassed {
				b.minRttTimestamp = now
				if b.debug {
					b.debugPrint("MinRTT: %s", b.getMinRtt())
				}
				if !b.isAtFullBandwidth {
					b.enterStartupMode(now)
				} else {
					b.enterProbeBandwidthMode(now)
				}
			}
		}
	}

	b.exitingQuiescence = false
}

// 判断 BBR 是否需要进入恢复、退出恢复或推进恢复状态。
func (b *bbrSender) updateRecoveryState(lastAckedPacket congestion.PacketNumber, hasLosses, isRoundStart bool) {
	// 如果启用了基于丢包的退出机制，则在 STARTUP 中禁用恢复。
	if !b.isAtFullBandwidth {
		return
	}

	// 一轮内没有丢包时退出恢复。
	if hasLosses {
		b.endRecoveryAt = b.lastSentPacket
	}

	switch b.recoveryState {
	case bbrRecoveryStateNotInRecovery:
		if hasLosses {
			b.recoveryState = bbrRecoveryStateConservation
			// 这会使 CalculateRecoveryWindow() 将 |recovery_window_| 设为正确值。
			b.recoveryWindow = 0
			// 由于守恒阶段应持续整整一轮，因此将当前轮次延长，视作此刻刚刚开始。
			b.currentRoundTripEnd = b.lastSentPacket
		}
	case bbrRecoveryStateConservation:
		if isRoundStart {
			b.recoveryState = bbrRecoveryStateGrowth
		}
		fallthrough
	case bbrRecoveryStateGrowth:
		// 在适当时退出恢复。
		if !hasLosses && lastAckedPacket > b.endRecoveryAt {
			b.recoveryState = bbrRecoveryStateNotInRecovery
		}
	}
}

// 确定连接合适的 pacing 速率。
func (b *bbrSender) calculatePacingRate(bytesLost congestion.ByteCount) {
	if b.bandwidthEstimate() == 0 {
		return
	}

	targetRate := Bandwidth(b.pacingGain * float64(b.bandwidthEstimate()))
	if b.isAtFullBandwidth {
		b.pacingRate = targetRate
		return
	}

	// 一旦有 RTT 测量值，就按 initial_window / RTT 的速率进行 pacing。
	if b.pacingRate == 0 && b.rttStats.MinRTT() != 0 {
		b.pacingRate = BandwidthFromDelta(b.initialCongestionWindow, b.rttStats.MinRTT())
		return
	}

	if b.detectOvershooting {
		b.bytesLostWhileDetectingOvershooting += bytesLost
		// 当 pacing 速率 > target_rate 且检测到丢包时，检查调整网络参数后的超调情况。
		if b.pacingRate > targetRate && b.bytesLostWhileDetectingOvershooting > 0 {
			if b.hasNoAppLimitedSample ||
				b.bytesLostWhileDetectingOvershooting*congestion.ByteCount(b.bytesLostMultiplierWhileDetectingOvershooting) > b.initialCongestionWindow {
				// 如果 1) 至少有一个非 app-limited 带宽样本，或 2) 一半 IW 丢失，
				// 则可以较有把握地认为发生了超调。降低 pacing 速率。
				b.pacingRate = max(targetRate, BandwidthFromDelta(b.cwndToCalculateMinPacingRate, b.rttStats.MinRTT()))
				b.bytesLostWhileDetectingOvershooting = 0
				b.detectOvershooting = false
			}
		}
	}

	// STARTUP 期间不要降低 pacing 速率。
	b.pacingRate = max(b.pacingRate, targetRate)
}

// 确定连接合适的拥塞窗口。
func (b *bbrSender) calculateCongestionWindow(bytesAcked, excessAcked congestion.ByteCount) {
	if b.mode == bbrModeProbeRtt {
		return
	}

	targetWindow := b.getTargetCongestionWindow(b.congestionWindowGain)
	if b.isAtFullBandwidth {
		// 将最近测得的最大 ack 聚合量加入 CWND。
		targetWindow += b.sampler.MaxAckHeight()
	} else if b.enableAckAggregationDuringStartup {
		// 加入最近一次确认的超额字节数。由于 STARTUP 中 CWND 不会减小，这会自动形成一个局部最大值滤波器。
		targetWindow += excessAcked
	}

	// BBR 不会立即将目标 CWND 设为新值，而是每次只增加 |bytes_acked|，逐步将 CWND 提升至 |target_window|。
	if b.isAtFullBandwidth {
		b.congestionWindow = min(targetWindow, b.congestionWindow+bytesAcked)
	} else if b.congestionWindow < targetWindow ||
		b.sampler.TotalBytesAcked() < b.initialCongestionWindow {
		// 如果连接尚未退出启动阶段，则不要缩小窗口。
		b.congestionWindow += bytesAcked
	}

	// 强制执行拥塞窗口限制。
	b.congestionWindow = max(b.congestionWindow, b.minCongestionWindow)
	b.congestionWindow = min(b.congestionWindow, b.maxCongestionWindow)
}

// 确定恢复期间用于限制在途数据的合适窗口。
func (b *bbrSender) calculateRecoveryWindow(bytesAcked, bytesLost congestion.ByteCount) {
	if b.recoveryState == bbrRecoveryStateNotInRecovery {
		return
	}

	// 设置初始恢复窗口。
	if b.recoveryWindow == 0 {
		b.recoveryWindow = b.bytesInFlight + bytesAcked
		b.recoveryWindow = max(b.minCongestionWindow, b.recoveryWindow)
		return
	}

	// 从恢复窗口中扣除丢失量，同时处理可能发生的整数下溢。
	if b.recoveryWindow >= bytesLost {
		b.recoveryWindow = b.recoveryWindow - bytesLost
	} else {
		b.recoveryWindow = b.maxDatagramSize
	}

	// 在 CONSERVATION 模式下，只需扣除丢失量即可。在 GROWTH 模式下，额外释放 |bytes_acked|，以实现类似慢启动的行为。
	if b.recoveryState == bbrRecoveryStateGrowth {
		b.recoveryWindow += bytesAcked
	}

	// 始终至少允许发送 |bytes_acked| 作为响应。
	b.recoveryWindow = max(b.recoveryWindow, b.bytesInFlight+bytesAcked)
	b.recoveryWindow = max(b.minCongestionWindow, b.recoveryWindow)
}

// 返回是否应因丢包过多而退出 STARTUP。
func (b *bbrSender) shouldExitStartupDueToLoss(lastPacketSendState *sendTimeState) bool {
	if b.numLossEventsInRound < defaultStartupFullLossCount || !lastPacketSendState.isValid {
		return false
	}

	inflightAtSend := lastPacketSendState.bytesInFlight

	if inflightAtSend > 0 && b.bytesLostInRound > 0 {
		if b.bytesLostInRound > congestion.ByteCount(float64(inflightAtSend)*quicBbr2DefaultLossThreshold) {
			return true
		}
		return false
	}
	return false
}

func (b *bbrSender) debugPrint(format string, a ...any) {
	fmt.Printf("[BBRSender] [%s] %s\n",
		time.Now().Format("15:04:05"),
		fmt.Sprintf(format, a...))
}

func bdpFromRttAndBandwidth(rtt time.Duration, bandwidth Bandwidth) congestion.ByteCount {
	return congestion.ByteCount(rtt) * congestion.ByteCount(bandwidth) / congestion.ByteCount(BytesPerSecond) / congestion.ByteCount(time.Second)
}

func GetInitialPacketSize(addr net.Addr) congestion.ByteCount {
	// 如果这不是 UDP 地址，我们就无法获知 MTU。
	// 使用 Initial 数据包的最小尺寸作为最大数据包尺寸。
	if _, ok := addr.(*net.UDPAddr); ok {
		return congestion.InitialPacketSize
	} else {
		return congestion.MinInitialPacketSize
	}
}

func formatSpeed(bw Bandwidth) string {
	bwf := float64(bw)
	units := []string{"bps", "Kbps", "Mbps", "Gbps"}
	unitIndex := 0
	for bwf > 1000 && unitIndex < len(units)-1 {
		bwf /= 1000
		unitIndex++
	}
	return fmt.Sprintf("%.2f %s", bwf, units[unitIndex])
}
