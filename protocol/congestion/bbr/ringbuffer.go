package bbr

// RingBuffer 是一个环形缓冲区。
// 它的行为类似堆，但不会产生任何内存分配。
type RingBuffer[T any] struct {
	ring             []T
	headPos, tailPos int
	full             bool
}

// Init 预分配指定大小的缓冲区。
func (r *RingBuffer[T]) Init(size int) {
	r.ring = make([]T, size)
}

// Len 返回环形缓冲区中的元素数量。
func (r *RingBuffer[T]) Len() int {
	if r.full {
		return len(r.ring)
	}
	if r.tailPos >= r.headPos {
		return r.tailPos - r.headPos
	}
	return r.tailPos - r.headPos + len(r.ring)
}

// Empty 返回环形缓冲区是否为空。
func (r *RingBuffer[T]) Empty() bool {
	return !r.full && r.headPos == r.tailPos
}

// PushBack 添加一个新元素。
// 如果环形缓冲区已满，则先扩展其容量。
func (r *RingBuffer[T]) PushBack(t T) {
	if r.full || len(r.ring) == 0 {
		r.grow()
	}
	r.ring[r.tailPos] = t
	r.tailPos++
	if r.tailPos == len(r.ring) {
		r.tailPos = 0
	}
	if r.tailPos == r.headPos {
		r.full = true
	}
}

// PopFront 返回下一个元素。
// 缓冲区为空时不得调用，因此调用方可能需要先检查缓冲区中是否有元素。
func (r *RingBuffer[T]) PopFront() T {
	if r.Empty() {
		panic("github.com/quic-go/quic-go/internal/utils/ringbuffer: pop from an empty queue")
	}
	r.full = false
	t := r.ring[r.headPos]
	r.ring[r.headPos] = *new(T)
	r.headPos++
	if r.headPos == len(r.ring) {
		r.headPos = 0
	}
	return t
}

// Offset 返回指定偏移处的元素。
// 缓冲区为空时不得调用，因此调用方可能需要先检查缓冲区中是否有元素，
// 并确认索引没有超出缓冲区长度。
func (r *RingBuffer[T]) Offset(index int) *T {
	if r.Empty() || index >= r.Len() {
		panic("github.com/quic-go/quic-go/internal/utils/ringbuffer: offset from invalid index")
	}
	offset := (r.headPos + index) % len(r.ring)
	return &r.ring[offset]
}

// Front 返回首元素。
// 缓冲区为空时不得调用，因此调用方可能需要先检查缓冲区中是否有元素。
func (r *RingBuffer[T]) Front() *T {
	if r.Empty() {
		panic("github.com/quic-go/quic-go/internal/utils/ringbuffer: front from an empty queue")
	}
	return &r.ring[r.headPos]
}

// Back 返回末元素。
// 缓冲区为空时不得调用，因此调用方可能需要先检查缓冲区中是否有元素。
func (r *RingBuffer[T]) Back() *T {
	if r.Empty() {
		panic("github.com/quic-go/quic-go/internal/utils/ringbuffer: back from an empty queue")
	}
	return r.Offset(r.Len() - 1)
}

// 扩大队列的最大容量。
// 此方法假定队列已满。
func (r *RingBuffer[T]) grow() {
	oldRing := r.ring
	newSize := len(oldRing) * 2
	if newSize == 0 {
		newSize = 1
	}
	r.ring = make([]T, newSize)
	headLen := copy(r.ring, oldRing[r.headPos:])
	copy(r.ring[headLen:], oldRing[:r.headPos])
	r.headPos, r.tailPos, r.full = 0, len(oldRing), false
}

// Clear 移除所有元素。
func (r *RingBuffer[T]) Clear() {
	var zeroValue T
	for i := range r.ring {
		r.ring[i] = zeroValue
	}
	r.headPos, r.tailPos, r.full = 0, 0, false
}
