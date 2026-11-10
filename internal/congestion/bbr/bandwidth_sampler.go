package bbr

import (
	"math"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

const (
	infRTT                             = time.Duration(math.MaxInt64)
	defaultConnectionStateMapQueueSize = 256
	defaultCandidatesBufferSize        = 256
)

type roundTripCount uint64

// SendTimeState 是 ConnectionStateOnSentPacket 的一个子集，在数据包得到 ack 或丢失时返回给调用方。
type sendTimeState struct {
	// 此对象中的其他状态是否有效。
	isValid bool
	// 发送数据包时，发送端是否受应用数据量限制（app-limited）。
	// 由于发送端没有足够的数据来填满链路，app-limited 带宽样本可能会人为偏低。
	isAppLimited bool
	// 发送该数据包时已发送的总字节数。
	// 包含该数据包本身。
	totalBytesSent congestion.ByteCount
	// 发送该数据包时已得到 ack 的总字节数。
	totalBytesAcked congestion.ByteCount
	// 发送该数据包时已丢失的总字节数。
	totalBytesLost congestion.ByteCount
	// 发送该数据包时的在途总字节数。
	// 包含该数据包本身。
	// 该值应等于 |total_bytes_sent| 减去 |total_bytes_acked|、|total_bytes_lost| 和已废弃字节数之和。
	bytesInFlight congestion.ByteCount
}

func newSendTimeState(
	isAppLimited bool,
	totalBytesSent congestion.ByteCount,
	totalBytesAcked congestion.ByteCount,
	totalBytesLost congestion.ByteCount,
	bytesInFlight congestion.ByteCount,
) *sendTimeState {
	return &sendTimeState{
		isValid:         true,
		isAppLimited:    isAppLimited,
		totalBytesSent:  totalBytesSent,
		totalBytesAcked: totalBytesAcked,
		totalBytesLost:  totalBytesLost,
		bytesInFlight:   bytesInFlight,
	}
}

type extraAckedEvent struct {
	// 此事件对应时间间隔内超额 ack 的字节数。
	extraAcked congestion.ByteCount

	// 此事件中得到 ack 的字节数及其时间间隔。
	bytesAcked congestion.ByteCount
	timeDelta  time.Duration
	// 此事件所属的往返轮次。
	round roundTripCount
}

func maxExtraAckedEventFunc(a, b extraAckedEvent) int {
	if a.extraAcked > b.extraAcked {
		return 1
	} else if a.extraAcked < b.extraAcked {
		return -1
	}
	return 0
}

// BandwidthSample 表示一个带宽样本。
type bandwidthSample struct {
	// 此样本对应的带宽；没有有效带宽样本时为零。
	bandwidth Bandwidth
	// 此样本对应的 RTT 测量值；没有 RTT 样本时为零。未对延迟 ack 时间进行校正。
	rtt time.Duration
	// |send_rate| 根据当前被 ack 的数据包（'P'）以及 P 发送前已被 ack 的较早数据包计算。
	sendRate Bandwidth
	// 发送数据包时捕获的状态。
	stateAtSend sendTimeState
}

func newBandwidthSample() *bandwidthSample {
	return &bandwidthSample{
		sendRate: infBandwidth,
	}
}

// MaxAckHeightTracker 是 BandwidthSampler 的一部分，在每次 ack 事件后调用，用于跟踪 ack 聚合程度（即“ack height”）。
type maxAckHeightTracker struct {
	// 跟踪 ack 速度超过估计带宽时，超额 ack 的最大字节数。
	maxAckHeightFilter *WindowedFilter[extraAckedEvent, roundTripCount]
	// 此次聚合的开始时间以及期间 ack 的字节数。
	aggregationEpochStartTime monotime.Time
	aggregationEpochBytes     congestion.ByteCount
	// 当前聚合周期开始前最后发送的数据包编号。
	lastSentPacketNumberBeforeEpoch congestion.PacketNumber
	// 已开始的 ack 聚合周期数，包括当前周期。仅用于统计。
	numAckAggregationEpochs                uint64
	ackAggregationBandwidthThreshold       float64
	startNewAggregationEpochAfterFullRound bool
	reduceExtraAckedOnBandwidthIncrease    bool
}

func newMaxAckHeightTracker(windowLength roundTripCount) *maxAckHeightTracker {
	return &maxAckHeightTracker{
		maxAckHeightFilter:               NewWindowedFilter(windowLength, maxExtraAckedEventFunc),
		lastSentPacketNumberBeforeEpoch:  invalidPacketNumber,
		ackAggregationBandwidthThreshold: 1.0,
	}
}

func (m *maxAckHeightTracker) Get() congestion.ByteCount {
	return m.maxAckHeightFilter.GetBest().extraAcked
}

func (m *maxAckHeightTracker) Update(
	bandwidthEstimate Bandwidth,
	isNewMaxBandwidth bool,
	roundTripCount roundTripCount,
	lastSentPacketNumber congestion.PacketNumber,
	lastAckedPacketNumber congestion.PacketNumber,
	ackTime monotime.Time,
	bytesAcked congestion.ByteCount,
) congestion.ByteCount {
	forceNewEpoch := false

	if m.reduceExtraAckedOnBandwidthIncrease && isNewMaxBandwidth {
		// 保存并清除现有条目。
		best := m.maxAckHeightFilter.GetBest()
		secondBest := m.maxAckHeightFilter.GetSecondBest()
		thirdBest := m.maxAckHeightFilter.GetThirdBest()
		m.maxAckHeightFilter.Clear()

		// 重新计算后，将高度值重新插入滤波器。
		expectedBytesAcked := bytesFromBandwidthAndTimeDelta(bandwidthEstimate, best.timeDelta)
		if expectedBytesAcked < best.bytesAcked {
			best.extraAcked = best.bytesAcked - expectedBytesAcked
			m.maxAckHeightFilter.Update(best, best.round)
		}
		expectedBytesAcked = bytesFromBandwidthAndTimeDelta(bandwidthEstimate, secondBest.timeDelta)
		if expectedBytesAcked < secondBest.bytesAcked {
			secondBest.extraAcked = secondBest.bytesAcked - expectedBytesAcked
			m.maxAckHeightFilter.Update(secondBest, secondBest.round)
		}
		expectedBytesAcked = bytesFromBandwidthAndTimeDelta(bandwidthEstimate, thirdBest.timeDelta)
		if expectedBytesAcked < thirdBest.bytesAcked {
			thirdBest.extraAcked = thirdBest.bytesAcked - expectedBytesAcked
			m.maxAckHeightFilter.Update(thirdBest, thirdBest.round)
		}
	}

	// 如果本周期开始后发送的任意数据包已得到 ack，则开始一个新周期。
	if m.startNewAggregationEpochAfterFullRound &&
		m.lastSentPacketNumberBeforeEpoch != invalidPacketNumber &&
		lastAckedPacketNumber != invalidPacketNumber &&
		lastAckedPacketNumber > m.lastSentPacketNumberBeforeEpoch {
		forceNewEpoch = true
	}
	if m.aggregationEpochStartTime.IsZero() || forceNewEpoch {
		m.aggregationEpochBytes = bytesAcked
		m.aggregationEpochStartTime = ackTime
		m.lastSentPacketNumberBeforeEpoch = lastSentPacketNumber
		m.numAckAggregationEpochs++
		return 0
	}

	// 假设最大带宽估计正确，计算预期交付的字节数。
	aggregationDelta := ackTime.Sub(m.aggregationEpochStartTime)
	expectedBytesAcked := bytesFromBandwidthAndTimeDelta(bandwidthEstimate, aggregationDelta)
	// ack 到达速率小于或等于最大带宽时，立即重置当前聚合周期。
	if m.aggregationEpochBytes <= congestion.ByteCount(m.ackAggregationBandwidthThreshold*float64(expectedBytesAcked)) {
		// 重置并开始测量新的聚合周期。
		m.aggregationEpochBytes = bytesAcked
		m.aggregationEpochStartTime = ackTime
		m.lastSentPacketNumberBeforeEpoch = lastSentPacketNumber
		m.numAckAggregationEpochs++
		return 0
	}

	m.aggregationEpochBytes += bytesAcked

	// 计算相对于最大带宽预期值额外交付的字节数。
	extraBytesAcked := m.aggregationEpochBytes - expectedBytesAcked
	newEvent := extraAckedEvent{
		extraAcked: extraBytesAcked,
		bytesAcked: m.aggregationEpochBytes,
		timeDelta:  aggregationDelta,
	}
	m.maxAckHeightFilter.Update(newEvent, roundTripCount)
	return extraBytesAcked
}

func (m *maxAckHeightTracker) SetFilterWindowLength(length roundTripCount) {
	m.maxAckHeightFilter.SetWindowLength(length)
}

func (m *maxAckHeightTracker) Reset(newHeight congestion.ByteCount, newTime roundTripCount) {
	newEvent := extraAckedEvent{
		extraAcked: newHeight,
		round:      newTime,
	}
	m.maxAckHeightFilter.Reset(newEvent, newTime)
}

func (m *maxAckHeightTracker) SetAckAggregationBandwidthThreshold(threshold float64) {
	m.ackAggregationBandwidthThreshold = threshold
}

func (m *maxAckHeightTracker) SetStartNewAggregationEpochAfterFullRound(value bool) {
	m.startNewAggregationEpochAfterFullRound = value
}

func (m *maxAckHeightTracker) SetReduceExtraAckedOnBandwidthIncrease(value bool) {
	m.reduceExtraAckedOnBandwidthIncrease = value
}

func (m *maxAckHeightTracker) AckAggregationBandwidthThreshold() float64 {
	return m.ackAggregationBandwidthThreshold
}

func (m *maxAckHeightTracker) NumAckAggregationEpochs() uint64 {
	return m.numAckAggregationEpochs
}

// AckPoint 表示 ack 曲线上的一个点。
type ackPoint struct {
	ackTime         monotime.Time
	totalBytesAcked congestion.ByteCount
}

// RecentAckPoints 保存时间不同的最近两个 ack 点。
type recentAckPoints struct {
	ackPoints [2]ackPoint
}

func (r *recentAckPoints) Update(ackTime monotime.Time, totalBytesAcked congestion.ByteCount) {
	if ackTime.Before(r.ackPoints[1].ackTime) {
		r.ackPoints[1].ackTime = ackTime
	} else if ackTime.After(r.ackPoints[1].ackTime) {
		r.ackPoints[0] = r.ackPoints[1]
		r.ackPoints[1].ackTime = ackTime
	}

	r.ackPoints[1].totalBytesAcked = totalBytesAcked
}

func (r *recentAckPoints) Clear() {
	r.ackPoints[0] = ackPoint{}
	r.ackPoints[1] = ackPoint{}
}

func (r *recentAckPoints) MostRecentPoint() *ackPoint {
	return &r.ackPoints[1]
}

func (r *recentAckPoints) LessRecentPoint() *ackPoint {
	if r.ackPoints[0].totalBytesAcked != 0 {
		return &r.ackPoints[0]
	}

	return &r.ackPoints[1]
}

// ConnectionStateOnSentPacket 表示已发送数据包的信息，以及发送该数据包时的连接状态，
// 特别是当时最近一个已 ack 数据包的相关信息。
type connectionStateOnSentPacket struct {
	// 数据包的发送时间。
	sentTime monotime.Time
	// 数据包大小。
	size congestion.ByteCount
	// 发送该数据包时 |totalBytesSentAtLastAckedPacket| 的值。
	totalBytesSentAtLastAckedPacket congestion.ByteCount
	// 发送该数据包时 |lastAckedPacketSentTime| 的值。
	lastAckedPacketSentTime monotime.Time
	// 发送该数据包时 |lastAckedPacketAckTime| 的值。
	lastAckedPacketAckTime monotime.Time
	// 数据包得到 ack 或丢失时返回给拥塞控制器的发送时状态。
	sendTimeState sendTimeState
}

// 快照构造函数，记录带宽采样器的当前状态。
// |bytes_in_flight| 是数据包发送后立即计算的在途字节数。
func newConnectionStateOnSentPacket(
	sentTime monotime.Time,
	size congestion.ByteCount,
	bytesInFlight congestion.ByteCount,
	sampler *bandwidthSampler,
) *connectionStateOnSentPacket {
	return &connectionStateOnSentPacket{
		sentTime:                        sentTime,
		size:                            size,
		totalBytesSentAtLastAckedPacket: sampler.totalBytesSentAtLastAckedPacket,
		lastAckedPacketSentTime:         sampler.lastAckedPacketSentTime,
		lastAckedPacketAckTime:          sampler.lastAckedPacketAckTime,
		sendTimeState: *newSendTimeState(
			sampler.isAppLimited,
			sampler.totalBytesSent,
			sampler.totalBytesAcked,
			sampler.totalBytesLost,
			bytesInFlight,
		),
	}
}

// BandwidthSampler 跟踪已发送和已确认的数据包，并为每个得到确认的数据包生成一个带宽样本。
// 样本针对单个数据包采集且未经滤波；使用方必须自行对带宽样本进行滤波。在某些情况下，
// 采样器会在局部严重低估带宽，因此建议使用窗口至少为一个 RTT 的最大值滤波器。
//
// 此类根据两条曲线的斜率生成样本：随时间变化的已发送字节数，以及随时间变化的已确认接收字节数。
// 对每个得到确认的数据包，它都会分别根据两条曲线上各自两点间的斜率生成样本。请注意，
// 由于数据包丢失，两条曲线上的字节数可能逐渐相差越来越大，因此不能直接比较来自不同曲线的字节数。
//
// 显然，斜率样本应使用刚得到确认的数据包对应的点。将它们记为 S_1（当前数据包发送时的点）和
// A_1（当前数据包得到确认时的点）。不过，计算斜率需要每条线上各有两个点，因此估算带宽时还要
// 选择过去的一个数据包作为斜率计算的参照点。
//
// 为此，BandwidthSampler 始终跟踪最近确认的数据包，并将其信息与每个发出的数据包一同记录。
// 数据包得到确认时（A_1），不仅能获知该数据包自身的发送时间（S_1），还可获知它发送前最近一个
// 已确认数据包的信息（S_0 和 A_0）。
//
// 根据这些数据，发送速率和 ack 速率估算如下：
//
//	send_rate = (bytes(S_1) - bytes(S_0)) / (time(S_1) - time(S_0))
//	ack_rate = (bytes(A_1) - bytes(A_0)) / (time(A_1) - time(A_0))
//
// 直观来说，ack 速率就是我们希望作为带宽的速率。不过在某些情况下（例如 ack compression），
// 某个时点的 ack 速率可能高于数据最初的发送速率，这并不能反映真实带宽。因此我们以发送速率作为上界，
// 样本值为
//
//	rate_sample = min(send_rate, ack_rate)
//
// 采样器处理的一个重要边界情况是跟踪 app-limited 样本。“app-limited”有多种含义，且常被混用，
// 因此需要理解并区分这些含义。
//
// 含义 1：连接状态。没有待发送数据时，称连接受应用数据量限制（app-limited）。这意味着之后某些带宽样本
// 无法准确反映链路容量，因此需要将此情况告知使用方。连接进入 app-limited 状态时，会通过 OnAppLimited()
// 方法通知采样器。
//
// 含义 2：带宽采样器中的一个阶段。采样器收到连接处于 app-limited 状态的通知后，便进入 app-limited 阶段。
// 在此阶段，所有*发送的*数据包都会标记为 app-limited。请注意，采样器处于 app-limited 阶段时，连接本身
// 不一定处于 app-limited 状态，实际上通常并非如此（否则它如何发送数据包？）。下面的布尔标志表示采样器是否处于该阶段。
//
// 含义 3：已发送数据包和样本上的一个标志。如果数据包在 app-limited 阶段发送，与该数据包关联的样本也会标记为 app-limited。
//
// 明确这些术语后，接下来看看它要处理哪类情况。
//
// 假设我们先以常规带宽发送数据包 1 到 20，随后立即耗尽待发送数据。几秒后开始发送数据包 21 到 60，
// 并且直到发送数据包 40 和 41 之间才收到数据包 21 的 ack。在这种情况下，为数据包 21 到 40 采样带宽时，
// 用于计算斜率的 S_0/A_0 会是数据包 20，与当前数据包相隔数秒，因此得到的估计值会极低且毫无代表性。
// 直到数据包 41，S_0/A_0 才会变为 21，这意味着带宽样本将排除这段静默期。
//
// 基于上述场景，我们实现了以下规则：调用 OnAppLimited() 后，所有已发送数据包都会生成 app-limited 样本，
// 直到某个在 OnAppLimited() 调用后发送的数据包得到 ack 为止。请注意，连接处于 app-limited 状态的场景并不只有上述一种，
// 但此方法同样适用于其他情况。

type congestionEventSample struct {
	// 所有已 ack 数据包中的最大带宽样本。
	// 没有样本时为 QuicBandwidth::Zero()。
	sampleMaxBandwidth Bandwidth
	// |sample_max_bandwidth| 是否来自 app-limited 样本。
	sampleIsAppLimited bool
	// 所有已 ack 数据包中的最小 RTT 样本。
	// 没有样本时为 QuicTime::Delta::Infinite()。
	sampleRtt time.Duration
	// 对已 ack 的每个数据包 p，此值为 INFLIGHT(p) 的最大值；
	// 其中 INFLIGHT(p) 是 p 处于在途状态期间得到 ack 的字节数。
	sampleMaxInflight congestion.ByteCount
	// acked_packets 非空时，取其中最大数据包的发送状态；如果 acked_packets 为空，
	// 则取 lost_packets 中最大数据包的发送状态。
	lastPacketSendState sendTimeState
	// 此 ack 事件中相对于流带宽预期值额外得到 ack 的字节数。该值越大，表示 ack 聚合程度越高。
	extraAcked congestion.ByteCount
}

func newCongestionEventSample() *congestionEventSample {
	return &congestionEventSample{
		sampleRtt: infRTT,
	}
}

type bandwidthSampler struct {
	// 连接期间发送的拥塞控制字节总数。
	totalBytesSent congestion.ByteCount

	// 已得到确认的拥塞控制字节总数。
	totalBytesAcked congestion.ByteCount

	// 已丢失的拥塞控制字节总数。
	totalBytesLost congestion.ByteCount

	// 已废弃的拥塞控制字节总数。
	totalBytesNeutered congestion.ByteCount

	// 最后一个已确认数据包发送时 |total_bytes_sent_| 的值。仅当 |last_acked_packet_sent_time_| 有效时才有效。
	totalBytesSentAtLastAckedPacket congestion.ByteCount

	// 最后一个已确认数据包的发送时间。没有有效时间戳时设为 QuicTime::Zero()。
	lastAckedPacketSentTime monotime.Time

	// 最近一个数据包得到确认的时间。
	lastAckedPacketAckTime monotime.Time

	// 最近发送的数据包。
	lastSentPacket congestion.PacketNumber

	// 最近得到 ack 的数据包。
	lastAckedPacket congestion.PacketNumber

	// 指示带宽采样器当前是否处于 app-limited 阶段。
	isAppLimited bool

	// 此数据包之后得到确认的数据包将使采样器退出 app-limited 阶段。
	endOfAppLimitedPhase congestion.PacketNumber

	// 按数据包编号索引的连接状态记录，保存每个在途数据包发送时的状态。
	connectionStateMap *packetNumberIndexedQueue[connectionStateOnSentPacket]

	recentAckPoints recentAckPoints
	a0Candidates    RingBuffer[ackPoint]

	// 跟踪的数据包数量上限。
	maxTrackedPackets congestion.ByteCount

	maxAckHeightTracker              *maxAckHeightTracker
	totalBytesAckedAfterLastAckEvent congestion.ByteCount

	// 如果设置了连接选项 'BSAO'，则为 true。
	overestimateAvoidance bool

	// 如果设置了连接选项 'BBRB'，则为 true。
	limitMaxAckHeightTrackerBySendRate bool
}

func newBandwidthSampler(maxAckHeightTrackerWindowLength roundTripCount) *bandwidthSampler {
	b := &bandwidthSampler{
		maxAckHeightTracker:  newMaxAckHeightTracker(maxAckHeightTrackerWindowLength),
		connectionStateMap:   newPacketNumberIndexedQueue[connectionStateOnSentPacket](defaultConnectionStateMapQueueSize),
		lastSentPacket:       invalidPacketNumber,
		lastAckedPacket:      invalidPacketNumber,
		endOfAppLimitedPhase: invalidPacketNumber,
	}

	b.a0Candidates.Init(defaultCandidatesBufferSize)

	return b
}

func (b *bandwidthSampler) MaxAckHeight() congestion.ByteCount {
	return b.maxAckHeightTracker.Get()
}

func (b *bandwidthSampler) NumAckAggregationEpochs() uint64 {
	return b.maxAckHeightTracker.NumAckAggregationEpochs()
}

func (b *bandwidthSampler) SetMaxAckHeightTrackerWindowLength(length roundTripCount) {
	b.maxAckHeightTracker.SetFilterWindowLength(length)
}

func (b *bandwidthSampler) ResetMaxAckHeightTracker(newHeight congestion.ByteCount, newTime roundTripCount) {
	b.maxAckHeightTracker.Reset(newHeight, newTime)
}

func (b *bandwidthSampler) SetStartNewAggregationEpochAfterFullRound(value bool) {
	b.maxAckHeightTracker.SetStartNewAggregationEpochAfterFullRound(value)
}

func (b *bandwidthSampler) SetLimitMaxAckHeightTrackerBySendRate(value bool) {
	b.limitMaxAckHeightTrackerBySendRate = value
}

func (b *bandwidthSampler) SetReduceExtraAckedOnBandwidthIncrease(value bool) {
	b.maxAckHeightTracker.SetReduceExtraAckedOnBandwidthIncrease(value)
}

func (b *bandwidthSampler) EnableOverestimateAvoidance() {
	if b.overestimateAvoidance {
		return
	}

	b.overestimateAvoidance = true
	b.maxAckHeightTracker.SetAckAggregationBandwidthThreshold(2.0)
}

func (b *bandwidthSampler) IsOverestimateAvoidanceEnabled() bool {
	return b.overestimateAvoidance
}

func (b *bandwidthSampler) OnPacketSent(
	sentTime monotime.Time,
	packetNumber congestion.PacketNumber,
	bytes congestion.ByteCount,
	bytesInFlight congestion.ByteCount,
	isRetransmittable bool,
) {
	b.lastSentPacket = packetNumber

	if !isRetransmittable {
		return
	}

	b.totalBytesSent += bytes

	// 如果当前没有在途数据包，则可以将新一轮传输开始的时间视为带宽采样中的 A_0 点。
	// 这会在一定程度上低估带宽，并使大多数在途数据包的样本人为偏低；但它能在一些重要时点提供样本，
	// 否则这些时点将没有样本，尤其是连接刚建立时。
	if bytesInFlight == 0 {
		b.lastAckedPacketAckTime = sentTime
		if b.overestimateAvoidance {
			b.recentAckPoints.Clear()
			b.recentAckPoints.Update(sentTime, b.totalBytesAcked)
			b.a0Candidates.Clear()
			b.a0Candidates.PushBack(*b.recentAckPoints.MostRecentPoint())
		}
		b.totalBytesSentAtLastAckedPacket = b.totalBytesSent

		// 此时无需担心 ack compression，因此将发送速率设为实际上无穷大。
		b.lastAckedPacketSentTime = sentTime
	}

	b.connectionStateMap.Emplace(packetNumber, newConnectionStateOnSentPacket(
		sentTime,
		bytes,
		bytesInFlight+bytes,
		b,
	))
}

func (b *bandwidthSampler) OnCongestionEvent(
	ackTime monotime.Time,
	ackedPackets []congestion.AckedPacketInfo,
	lostPackets []congestion.LostPacketInfo,
	maxBandwidth Bandwidth,
	estBandwidthUpperBound Bandwidth,
	roundTripCount roundTripCount,
) congestionEventSample {
	eventSample := newCongestionEventSample()

	var lastLostPacketSendState sendTimeState

	for _, p := range lostPackets {
		sendState := b.OnPacketLost(p.PacketNumber, p.BytesLost)
		if sendState.isValid {
			lastLostPacketSendState = sendState
		}
	}

	if len(ackedPackets) == 0 {
		// 仅丢包事件只填充发送状态。
		eventSample.lastPacketSendState = lastLostPacketSendState
		return *eventSample
	}

	var lastAckedPacketSendState sendTimeState
	var maxSendRate Bandwidth

	for _, p := range ackedPackets {
		sample := b.onPacketAcknowledged(ackTime, p.PacketNumber)
		if !sample.stateAtSend.isValid {
			continue
		}

		lastAckedPacketSendState = sample.stateAtSend

		if sample.rtt != 0 {
			eventSample.sampleRtt = min(eventSample.sampleRtt, sample.rtt)
		}
		if sample.bandwidth > eventSample.sampleMaxBandwidth {
			eventSample.sampleMaxBandwidth = sample.bandwidth
			eventSample.sampleIsAppLimited = sample.stateAtSend.isAppLimited
		}
		if sample.sendRate != infBandwidth {
			maxSendRate = max(maxSendRate, sample.sendRate)
		}
		inflightSample := b.totalBytesAcked - lastAckedPacketSendState.totalBytesAcked
		if inflightSample > eventSample.sampleMaxInflight {
			eventSample.sampleMaxInflight = inflightSample
		}
	}

	if !lastLostPacketSendState.isValid {
		eventSample.lastPacketSendState = lastAckedPacketSendState
	} else if !lastAckedPacketSendState.isValid {
		eventSample.lastPacketSendState = lastLostPacketSendState
	} else {
		// 如果有两个数据包在途，且用于判定数据包丢失的定时器晚触发，那么在定时器触发前，
		// 两个在途数据包中的第一个可能已经得到确认；这会重新评估丢包检测，并可能将后发送的那个判定为丢失。
		if lostPackets[len(lostPackets)-1].PacketNumber > ackedPackets[len(ackedPackets)-1].PacketNumber {
			eventSample.lastPacketSendState = lastLostPacketSendState
		} else {
			eventSample.lastPacketSendState = lastAckedPacketSendState
		}
	}

	isNewMaxBandwidth := eventSample.sampleMaxBandwidth > maxBandwidth
	maxBandwidth = max(maxBandwidth, eventSample.sampleMaxBandwidth)
	if b.limitMaxAckHeightTrackerBySendRate {
		maxBandwidth = max(maxBandwidth, maxSendRate)
	}

	eventSample.extraAcked = b.onAckEventEnd(min(estBandwidthUpperBound, maxBandwidth), isNewMaxBandwidth, roundTripCount)

	return *eventSample
}

func (b *bandwidthSampler) OnPacketLost(packetNumber congestion.PacketNumber, bytesLost congestion.ByteCount) (s sendTimeState) {
	b.totalBytesLost += bytesLost
	if sentPacketPointer := b.connectionStateMap.GetEntry(packetNumber); sentPacketPointer != nil {
		sentPacketToSendTimeState(sentPacketPointer, &s)
	}
	return s
}

func (b *bandwidthSampler) OnPacketNeutered(packetNumber congestion.PacketNumber) {
	b.connectionStateMap.Remove(packetNumber, func(sentPacket connectionStateOnSentPacket) {
		b.totalBytesNeutered += sentPacket.size
	})
}

func (b *bandwidthSampler) OnAppLimited() {
	b.isAppLimited = true
	b.endOfAppLimitedPhase = b.lastSentPacket
}

func (b *bandwidthSampler) RemoveObsoletePackets(leastUnacked congestion.PacketNumber) {
	// 数据包在得到 ack 或被标记为丢失之前，可能就已从 QuicUnackedPacketMap 的在途记录中移除，从而变为过时。
	// 例如，QuicSentPacketManager::RetransmitCryptoPackets 重传 crypto 数据包时，该数据包会从
	// QuicUnackedPacketMap 的在途记录中移除，但不会在 BandwidthSampler 中标记为已 ack 或丢失。
	b.connectionStateMap.RemoveUpTo(leastUnacked)
}

func (b *bandwidthSampler) TotalBytesSent() congestion.ByteCount {
	return b.totalBytesSent
}

func (b *bandwidthSampler) TotalBytesLost() congestion.ByteCount {
	return b.totalBytesLost
}

func (b *bandwidthSampler) TotalBytesAcked() congestion.ByteCount {
	return b.totalBytesAcked
}

func (b *bandwidthSampler) TotalBytesNeutered() congestion.ByteCount {
	return b.totalBytesNeutered
}

func (b *bandwidthSampler) IsAppLimited() bool {
	return b.isAppLimited
}

func (b *bandwidthSampler) EndOfAppLimitedPhase() congestion.PacketNumber {
	return b.endOfAppLimitedPhase
}

func (b *bandwidthSampler) max_ack_height() congestion.ByteCount {
	return b.maxAckHeightTracker.Get()
}

func (b *bandwidthSampler) chooseA0Point(totalBytesAcked congestion.ByteCount, a0 *ackPoint) bool {
	if b.a0Candidates.Empty() {
		return false
	}

	if b.a0Candidates.Len() == 1 {
		*a0 = *b.a0Candidates.Front()
		return true
	}

	for i := 1; i < b.a0Candidates.Len(); i++ {
		if b.a0Candidates.Offset(i).totalBytesAcked > totalBytesAcked {
			*a0 = *b.a0Candidates.Offset(i - 1)
			if i > 1 {
				for j := 0; j < i-1; j++ {
					b.a0Candidates.PopFront()
				}
			}
			return true
		}
	}

	*a0 = *b.a0Candidates.Back()
	for k := 0; k < b.a0Candidates.Len()-1; k++ {
		b.a0Candidates.PopFront()
	}
	return true
}

func (b *bandwidthSampler) onPacketAcknowledged(ackTime monotime.Time, packetNumber congestion.PacketNumber) bandwidthSample {
	sample := newBandwidthSample()
	b.lastAckedPacket = packetNumber
	sentPacketPointer := b.connectionStateMap.GetEntry(packetNumber)
	if sentPacketPointer == nil {
		return *sample
	}

	// OnPacketAcknowledgedInner。
	b.totalBytesAcked += sentPacketPointer.size
	b.totalBytesSentAtLastAckedPacket = sentPacketPointer.sendTimeState.totalBytesSent
	b.lastAckedPacketSentTime = sentPacketPointer.sentTime
	b.lastAckedPacketAckTime = ackTime
	if b.overestimateAvoidance {
		b.recentAckPoints.Update(ackTime, b.totalBytesAcked)
	}

	if b.isAppLimited {
		// 以下两种情况下退出 app-limited 阶段：
		// (1) end_of_app_limited_phase_ 尚未初始化，即此前发送的所有数据包发送时都有缓冲数据或待发送数据。
		// (2) 当前得到 ack 的数据包晚于标记为 app-limited 阶段结束点的已发送数据包。
		if b.endOfAppLimitedPhase == invalidPacketNumber ||
			packetNumber > b.endOfAppLimitedPhase {
			b.isAppLimited = false
		}
	}

	// 当前数据包发送时可能还没有任何数据包得到确认。在这种情况下，无法生成带宽样本。
	if sentPacketPointer.lastAckedPacketSentTime.IsZero() {
		return *sample
	}

	// 无穷大的速率表示采样器应丢弃当前发送速率样本，只使用 ack 速率。
	sendRate := infBandwidth
	if sentPacketPointer.sentTime.After(sentPacketPointer.lastAckedPacketSentTime) {
		sendRate = BandwidthFromDelta(
			sentPacketPointer.sendTimeState.totalBytesSent-sentPacketPointer.totalBytesSentAtLastAckedPacket,
			sentPacketPointer.sentTime.Sub(sentPacketPointer.lastAckedPacketSentTime),
		)
	}

	var a0 ackPoint
	if b.overestimateAvoidance && b.chooseA0Point(sentPacketPointer.sendTimeState.totalBytesAcked, &a0) {
	} else {
		a0.ackTime = sentPacketPointer.lastAckedPacketAckTime
		a0.totalBytesAcked = sentPacketPointer.sendTimeState.totalBytesAcked
	}

	// 计算斜率时，确保当前数据包的 ack 时间始终晚于前一个数据包的时间，否则可能发生除零或整数下溢。
	if ackTime.Sub(a0.ackTime) <= 0 {
		return *sample
	}

	ackRate := BandwidthFromDelta(b.totalBytesAcked-a0.totalBytesAcked, ackTime.Sub(a0.ackTime))

	sample.bandwidth = min(sendRate, ackRate)
	// 注意：此样本未计入延迟确认时间。因此这里的 RTT 测量值可能人为偏高，尤其是在低带宽连接上。
	sample.rtt = ackTime.Sub(sentPacketPointer.sentTime)
	sample.sendRate = sendRate
	sentPacketToSendTimeState(sentPacketPointer, &sample.stateAtSend)

	return *sample
}

func (b *bandwidthSampler) onAckEventEnd(
	bandwidthEstimate Bandwidth,
	isNewMaxBandwidth bool,
	roundTripCount roundTripCount,
) congestion.ByteCount {
	newlyAckedBytes := b.totalBytesAcked - b.totalBytesAckedAfterLastAckEvent
	if newlyAckedBytes == 0 {
		return 0
	}
	b.totalBytesAckedAfterLastAckEvent = b.totalBytesAcked
	extraAcked := b.maxAckHeightTracker.Update(
		bandwidthEstimate,
		isNewMaxBandwidth,
		roundTripCount,
		b.lastSentPacket,
		b.lastAckedPacket,
		b.lastAckedPacketAckTime,
		newlyAckedBytes,
	)
	// 如果 |extra_acked| 为零，即此 ack 事件标志着新的 ack 聚合周期开始，则将 LessRecentPoint
	//（上一周期最后一个 ack 点）保存为 A0 候选点。
	if b.overestimateAvoidance && extraAcked == 0 {
		b.a0Candidates.PushBack(*b.recentAckPoints.LessRecentPoint())
	}
	return extraAcked
}

func sentPacketToSendTimeState(sentPacket *connectionStateOnSentPacket, sendTimeState *sendTimeState) {
	*sendTimeState = sentPacket.sendTimeState
	sendTimeState.isValid = true
}

// BytesFromBandwidthAndTimeDelta 根据带宽（bits per second）和时间间隔计算字节数。
func bytesFromBandwidthAndTimeDelta(bandwidth Bandwidth, delta time.Duration) congestion.ByteCount {
	return (congestion.ByteCount(bandwidth) * congestion.ByteCount(delta)) /
		(congestion.ByteCount(time.Second) * 8)
}

func timeDeltaFromBytesAndBandwidth(bytes congestion.ByteCount, bandwidth Bandwidth) time.Duration {
	return time.Duration(bytes*8) * time.Second / time.Duration(bandwidth)
}
