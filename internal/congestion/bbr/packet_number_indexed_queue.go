package bbr

import (
	"github.com/apernet/quic-go/congestion"
)

// packetNumberIndexedQueue 是一个存储编号大致连续条目的队列，支持以下操作：
// - 在队尾或队尾之后的任意位置添加元素
// - 按任意顺序移除元素
// - 获取元素
// 如果所有元素都按顺序插入，上述操作的摊销时间复杂度均为 O(1)。
//
// 内部数据结构是一个双端队列，每个元素都会标记为存在或不存在。双端队列从最小的有效索引开始。
// 每当移除元素时，会将其标记为不存在，并清除双端队列队首所有标记为不存在的元素。
//
// 由于假定条目按顺序插入，队列尾部不会被清理；不过，移除队列中的所有元素后，队列会恢复到初始状态。
//
// 请注意，这种数据结构本身存在风险：仅添加两个条目就可能耗尽所有可用内存。
// 因此，它不是通用容器，不应当作为通用容器使用。

type entryWrapper[T any] struct {
	present bool
	entry   T
}

type packetNumberIndexedQueue[T any] struct {
	entries                RingBuffer[entryWrapper[T]]
	numberOfPresentEntries int
	firstPacket            congestion.PacketNumber
}

func newPacketNumberIndexedQueue[T any](size int) *packetNumberIndexedQueue[T] {
	q := &packetNumberIndexedQueue[T]{
		firstPacket: invalidPacketNumber,
	}

	q.entries.Init(size)

	return q
}

// Emplace 将与 |packet_number| 关联的数据插入队尾或其后的位置，并按需填充缺失的中间条目。
// 插入成功时返回 true；如果元素已在队列中或插入顺序不正确，则返回 false。
func (p *packetNumberIndexedQueue[T]) Emplace(packetNumber congestion.PacketNumber, entry *T) bool {
	if packetNumber == invalidPacketNumber || entry == nil {
		return false
	}

	if p.IsEmpty() {
		p.entries.PushBack(entryWrapper[T]{
			present: true,
			entry:   *entry,
		})
		p.numberOfPresentEntries = 1
		p.firstPacket = packetNumber
		return true
	}

	// 不允许乱序插入。
	if packetNumber <= p.LastPacket() {
		return false
	}

	// 处理可能缺失的元素。
	offset := int(packetNumber - p.FirstPacket())
	if gap := offset - p.entries.Len(); gap > 0 {
		for i := 0; i < gap; i++ {
			p.entries.PushBack(entryWrapper[T]{})
		}
	}

	p.entries.PushBack(entryWrapper[T]{
		present: true,
		entry:   *entry,
	})
	p.numberOfPresentEntries++
	return true
}

// GetEntry 获取与数据包编号关联的条目。成功时返回指向该条目的指针；条目不存在时返回 nullptr。
func (p *packetNumberIndexedQueue[T]) GetEntry(packetNumber congestion.PacketNumber) *T {
	ew := p.getEntryWraper(packetNumber)
	if ew == nil {
		return nil
	}

	return &ew.entry
}

// Remove 与上面类似，但如果队列中存在该条目，还会在移除前调用 f(entry)。
func (p *packetNumberIndexedQueue[T]) Remove(packetNumber congestion.PacketNumber, f func(T)) bool {
	ew := p.getEntryWraper(packetNumber)
	if ew == nil {
		return false
	}
	if f != nil {
		f(ew.entry)
	}
	ew.present = false
	p.numberOfPresentEntries--

	if packetNumber == p.FirstPacket() {
		p.clearup()
	}

	return true
}

// 移除直到 |packet_number| 之前的所有条目，但不包括 |packet_number|。
// 队首未使用的槽位也会一并移除，因此函数返回时，|first_packet()| 可能大于 |packet_number|。
func (p *packetNumberIndexedQueue[T]) RemoveUpTo(packetNumber congestion.PacketNumber) {
	for !p.entries.Empty() &&
		p.firstPacket != invalidPacketNumber &&
		p.firstPacket < packetNumber {
		if p.entries.Front().present {
			p.numberOfPresentEntries--
		}
		p.entries.PopFront()
		p.firstPacket++
	}
	p.clearup()

	return
}

// IsEmpty 返回队列是否为空。
func (p *packetNumberIndexedQueue[T]) IsEmpty() bool {
	return p.numberOfPresentEntries == 0
}

// NumberOfPresentEntries 返回队列中的条目数。
func (p *packetNumberIndexedQueue[T]) NumberOfPresentEntries() int {
	return p.numberOfPresentEntries
}

// EntrySlotsUsed 返回底层双端队列已分配的条目数，该值与队列的内存用量成正比。
func (p *packetNumberIndexedQueue[T]) EntrySlotsUsed() int {
	return p.entries.Len()
}

// FirstPacket 返回队列中第一个条目的数据包编号。
func (p *packetNumberIndexedQueue[T]) FirstPacket() (packetNumber congestion.PacketNumber) {
	return p.firstPacket
}

// LastPacket 返回曾插入队列的最后一个条目的数据包编号。请注意，该条目可能已经被移除。
// 队列为空时返回 0。
func (p *packetNumberIndexedQueue[T]) LastPacket() (packetNumber congestion.PacketNumber) {
	if p.IsEmpty() {
		return invalidPacketNumber
	}

	return p.firstPacket + congestion.PacketNumber(p.entries.Len()-1)
}

func (p *packetNumberIndexedQueue[T]) clearup() {
	for !p.entries.Empty() && !p.entries.Front().present {
		p.entries.PopFront()
		p.firstPacket++
	}
	if p.entries.Empty() {
		p.firstPacket = invalidPacketNumber
	}
}

func (p *packetNumberIndexedQueue[T]) getEntryWraper(packetNumber congestion.PacketNumber) *entryWrapper[T] {
	if packetNumber == invalidPacketNumber ||
		p.IsEmpty() ||
		packetNumber < p.firstPacket {
		return nil
	}

	offset := int(packetNumber - p.firstPacket)
	if offset >= p.entries.Len() {
		return nil
	}

	ew := p.entries.Offset(offset)
	if ew == nil || !ew.present {
		return nil
	}

	return ew
}
